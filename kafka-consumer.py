#!/usr/bin/env python3
"""
siem_consumer.py

Complete SIEM Kafka consumer with MongoDB storage and Sigma rule evaluation.
Usage:
    python siem_consumer.py            # run consumer (consume live from Kafka)
    python siem_consumer.py --recheck  # load rules and re-evaluate all logs in MongoDB
"""

import argparse
import json
import re
import time
import hashlib
from datetime import datetime
from pathlib import Path

import yaml
from dateutil import parser as dateparser
from kafka import KafkaConsumer
from pymongo import MongoClient, ASCENDING

# -------------------------
# Configuration
# -------------------------
KAFKA_BOOTSTRAP = ['localhost:19092']
KAFKA_TOPICS = ['application', 'system']  # REMOVED 'security'
MONGO_URI = "mongodb+srv://qadrshah2_db_user:ZPaM7R7iPcWwmJvP@logtracks.0aqgjwm.mongodb.net/"
MONGO_DB = "logtracks_db"
LOGS_COLLECTION_NAME = "normalized_logs"
ALERTS_COLLECTION_NAME = "alerts"
SIGMA_RULES_FOLDER = "./sigma_rules"
NORMALIZED_EVENTS_FILE = "normalized_events.jsonl"


# -------------------------
# MongoDB helpers
# -------------------------
def get_mongo_collections():
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        logs_collection = db[LOGS_COLLECTION_NAME]
        alerts_collection = db[ALERTS_COLLECTION_NAME]

        # Ensure index for alert dedupe
        alerts_collection.create_index([("alert_id", ASCENDING)], unique=True, background=True)
        print("✅ Connected to MongoDB Atlas successfully!")
        return logs_collection, alerts_collection, client
    except Exception as e:
        print(f"❌ MongoDB connection error: {e}")
        return None, None, None


# -------------------------
# Enhanced Sigma rule implementation
# -------------------------
def _get_field_from_event(event, key):
    """
    Support nested keys using dot notation to fetch values from event dicts.
    """
    if not isinstance(event, dict):
        return None
    cur = event
    for part in key.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return None
    return cur


class EnhancedSigmaRule:
    """
    Enhanced Sigma rule container and matcher with better field mapping and condition support.
    """

    def __init__(self, yaml_data, source_path=None):
        self.source_path = source_path
        self.title = yaml_data.get('title', 'Unnamed Rule')
        self.description = yaml_data.get('description', '')
        self.level = yaml_data.get('level', yaml_data.get('severity', 'medium'))
        self.detection = yaml_data.get('detection', {})
        self.logsource = yaml_data.get('logsource', {})
        self.falsepositives = yaml_data.get('falsepositives', [])
        self.condition = self.detection.pop('condition', 'all of them')

    def _get_nested_value(self, event, field_path):
        """Get nested field value using multiple lookup strategies"""
        if not field_path or not isinstance(event, dict):
            return None

        # Try multiple field path strategies
        paths_to_try = [
            field_path,
            f"winlog.event_data.{field_path}",
            f"event_data.{field_path}",
            field_path.replace('EventData.', 'winlog.event_data.'),
            field_path.replace('EventData.', '')
        ]

        for path in paths_to_try:
            current = event
            for key in path.split('.'):
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    current = None
                    break
            if current is not None:
                return current

        # Try case-insensitive search in flattened structure
        field_lower = field_path.lower()
        for key, value in event.items():
            if key.lower() == field_lower:
                return value

        return None

    def _evaluate_condition(self, value, condition):
        """Evaluate a single condition against a value"""
        if value is None:
            return False

        # Handle list of values
        if isinstance(value, (list, tuple)):
            return any(self._evaluate_condition(item, condition) for item in value)

        str_value = str(value).lower()

        # Dictionary condition with operators
        if isinstance(condition, dict):
            for operator, expected in condition.items():
                operator = operator.lower()
                expected_str = str(expected).lower() if expected is not None else ""

                if operator == 'contains':
                    if expected_str not in str_value:
                        return False
                elif operator == 'equals':
                    if str_value != expected_str:
                        return False
                elif operator == 'startswith':
                    if not str_value.startswith(expected_str):
                        return False
                elif operator == 'endswith':
                    if not str_value.endswith(expected_str):
                        return False
                elif operator == 'regex':
                    try:
                        if not re.search(expected, str(value)):
                            return False
                    except re.error:
                        return False
                elif operator == 'in':
                    if isinstance(expected, (list, tuple)):
                        if str_value not in [str(x).lower() for x in expected]:
                            return False
                    else:
                        if str_value != expected_str:
                            return False
                else:
                    return False
            return True

        # String condition (default to contains)
        elif isinstance(condition, str):
            return str(condition).lower() in str_value

        # List condition (any match)
        elif isinstance(condition, (list, tuple)):
            return any(self._evaluate_condition(value, item) for item in condition)

        return False

    def _evaluate_detection_item(self, event, item_name, condition):
        """Evaluate a single detection item against the event"""
        # Field-based search
        if isinstance(condition, dict) and any(op in condition for op in
                                               ['contains', 'equals', 'startswith', 'endswith', 'regex', 'in']):
            # Single field condition
            for field, field_condition in condition.items():
                if field in ['contains', 'equals', 'startswith', 'endswith', 'regex', 'in']:
                    continue

                value = self._get_nested_value(event, field)
                if value is not None:
                    # Extract the operator and expected value
                    operator = list(condition.keys())[0]
                    expected = condition[operator]
                    return self._evaluate_condition(value, {operator: expected})
            return False

        else:
            # Keyword search - search across all string fields
            search_text = ' '.join(str(v) for v in self._flatten_dict(event).values()
                                   if isinstance(v, (str, int, float)))
            return self._evaluate_condition(search_text, condition)

    def _flatten_dict(self, d, parent_key='', sep='.'):
        """Flatten a nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def matches(self, event):
        """Evaluate if event matches this Sigma rule"""
        if not isinstance(event, dict):
            return False

        # Use raw event data for matching
        raw_event = event.get('raw', event)

        # Evaluate each detection criteria
        criteria_results = {}
        for criteria_name, condition in self.detection.items():
            if criteria_name == 'condition':
                continue

            criteria_results[criteria_name] = self._evaluate_detection_item(raw_event, criteria_name, condition)

        # Evaluate condition logic
        if not criteria_results:
            return False

        condition_str = str(self.condition).lower()

        if 'all of them' in condition_str:
            return all(criteria_results.values())
        elif 'any of them' in condition_str or '1 of them' in condition_str:
            return any(criteria_results.values())
        elif 'all of' in condition_str:
            # Extract selection names after 'all of'
            selection_names = re.findall(r'all of\s*([^\s|]+)', condition_str)
            if selection_names:
                return all(criteria_results.get(name.strip(), False) for name in selection_names)
            return all(criteria_results.values())
        elif 'any of' in condition_str or '1 of' in condition_str:
            # Extract selection names
            selection_names = re.findall(r'(?:any|1) of\s*([^\s|]+)', condition_str)
            if selection_names:
                return any(criteria_results.get(name.strip(), False) for name in selection_names)
            return any(criteria_results.values())
        else:
            # Default to AND logic
            return all(criteria_results.values())


# -------------------------
# SIEM consumer
# -------------------------
class SIEMKafkaConsumer:
    def __init__(self, bootstrap_servers=None):
        self.bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP
        self.consumer = None
        self.running = False
        self.logs_collection, self.alerts_collection, self.mongo_client = get_mongo_collections()
        self.sigma_rules = []
        self.processed_count = 0
        self.last_log_time = time.time()

    # Kafka connection
    def connect(self):
        try:
            self.consumer = KafkaConsumer(
                *KAFKA_TOPICS,
                bootstrap_servers=self.bootstrap_servers,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                group_id='siem-consumer-group',
                value_deserializer=lambda m: json.loads(m.decode('utf-8')) if m else None,
                session_timeout_ms=30000,
                heartbeat_interval_ms=10000,
                max_poll_interval_ms=300000,
                fetch_max_bytes=1048576,
                max_partition_fetch_bytes=1048576,
                fetch_max_wait_ms=500
            )
            print("✅ Connected to Kafka successfully!")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to Kafka: {e}")
            return False

    # Normalization
    def normalize_event(self, topic, event):
        norm = {}
        ts = event.get('@timestamp') or event.get('timestamp') or event.get('time') or None
        try:
            dt = dateparser.parse(ts) if ts else datetime.utcnow()
        except Exception:
            dt = datetime.utcnow()
        norm['timestamp'] = dt.astimezone().isoformat() if hasattr(dt, "astimezone") else dt.isoformat()

        # host extraction
        host = None
        host_candidate = event.get('host')
        if isinstance(host_candidate, dict):
            host = host_candidate.get('name') or host_candidate.get('hostname')
        if not host:
            host = event.get('host') or event.get('agent', {}).get('name') or event.get('computer') or event.get(
                'hostname')

        norm['host'] = host

        # event id extraction (winlog or top-level)
        winlog = event.get('winlog') or {}
        event_id = None
        if isinstance(winlog, dict):
            event_id = winlog.get('event_id') or winlog.get('EventID') or winlog.get('EventID64')
        if not event_id:
            event_id = event.get('event_id') or event.get('id')
        try:
            norm['event_id'] = int(event_id) if event_id not in (None, '') else None
        except Exception:
            norm['event_id'] = None

        # source_ip heuristics
        source_ip = None
        for key in ('source_ip', 'src_ip', 'src', 'client.ip', 'ip', 'remote_ip'):
            val = event
            for part in key.split('.'):
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val:
                source_ip = val
                break
        norm['source_ip'] = source_ip

        # message
        message = event.get('message') or event.get('msg') or ''
        if not message and isinstance(winlog, dict):
            evdata = winlog.get('event_data') or winlog.get('EventData')
            if isinstance(evdata, dict):
                message = ' '.join(str(v) for v in evdata.values() if v)
        norm['message'] = message

        norm['event_type'] = topic or event.get('event_type') or event.get('type')
        norm['raw'] = event
        return norm

    def save_to_mongo(self, normalized_event):
        if self.logs_collection is None:
            print("⚠️ MongoDB not connected, skipping save.")
            return
        try:
            res = self.logs_collection.insert_one(normalized_event)
            # Only log every 10th save to reduce noise
            if self.processed_count % 10 == 0:
                print(f"💾 Saved event to MongoDB (id={res.inserted_id}).")
        except Exception as e:
            print(f"❌ MongoDB save error: {e}")

    def save_normalized_to_file(self, normalized_event, filename=NORMALIZED_EVENTS_FILE):
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(json.dumps(normalized_event, default=str) + "\n")
        except Exception as e:
            print(f"Error saving normalized event to file: {e}")

    # Sigma rules: loading & evaluation
    def load_sigma_rules(self, rules_folder=SIGMA_RULES_FOLDER):
        self.sigma_rules = []
        try:
            p = Path(rules_folder)
            if not p.exists():
                print(f"⚠️ Sigma rules folder not found at {rules_folder}. Create it and add .yml rule files.")
                return
            for path in p.rglob('*.yml'):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        yaml_data = yaml.safe_load(f)
                        if yaml_data and 'detection' in yaml_data:
                            self.sigma_rules.append(EnhancedSigmaRule(yaml_data, source_path=str(path)))
                            print(f"📁 Loaded rule: {yaml_data.get('title', 'Unnamed')}")
                except Exception as e:
                    print(f"⚠️ Failed to load {path}: {e}")
            print(f"🧠 Loaded {len(self.sigma_rules)} Sigma rules.")
        except Exception as e:
            print(f"❌ Error loading Sigma rules: {e}")

    def _build_alert_id(self, rule, event):
        """Build a dedupe key for alerts"""
        try:
            raw = event.get('raw', event)
            event_id = str(event.get('event_id') or raw.get('event_id') or '')
            host = str(event.get('host') or raw.get('host') or '')
            timestamp = str(event.get('timestamp') or '')

            unique_string = f"{rule.title}::{event_id}::{host}::{timestamp}"
            return hashlib.md5(unique_string.encode()).hexdigest()
        except Exception:
            return f"{rule.title}::{hash(json.dumps(event, default=str))}"

    def save_alert_to_mongo(self, rule, normalized_event, raw_event=None):
        if self.alerts_collection is None:
            return
        alert_id = self._build_alert_id(rule, normalized_event)
        alert_doc = {
            "alert_id": alert_id,
            "rule_title": rule.title,
            "description": rule.description,
            "level": rule.level,
            "detected_at": datetime.utcnow(),
            "normalized_event": normalized_event,
            "raw_event": raw_event or normalized_event.get('raw')
        }
        try:
            # upsert to avoid duplicates
            res = self.alerts_collection.update_one(
                {"alert_id": alert_id},
                {"$setOnInsert": alert_doc},
                upsert=True
            )
            if res.upserted_id:
                print(f"🚨 NEW ALERT: {rule.title} (Level: {rule.level})")
            # else: duplicate alert, don't spam the console
        except Exception as e:
            print(f"❌ Failed to save alert: {e}")

    def evaluate_sigma_rules(self, normalized_event):
        if not self.sigma_rules:
            print("⚠️ No Sigma rules loaded")
            return

        print(f"🔍 Evaluating {len(self.sigma_rules)} rules against event from {normalized_event.get('host')}")

        for rule in self.sigma_rules:
            try:
                if rule.matches(normalized_event):
                    print(f"\n🚨 [SIGMA ALERT] Rule matched: {rule.title}")
                    print(f"   📄 Description: {rule.description}")
                    print(f"   ⚙️ Level: {rule.level}")
                    print(f"   🖥️ Host: {normalized_event.get('host', 'N/A')}")
                    print(f"   🆔 Event ID: {normalized_event.get('event_id', 'N/A')}\n")
                    self.save_alert_to_mongo(rule, normalized_event)
            except Exception as e:
                print(f"❌ Error evaluating rule '{rule.title}': {e}")

    def recheck_mongo_logs(self):
        """Re-evaluate all logs currently present in MongoDB against loaded Sigma rules."""
        if self.logs_collection is None:
            print("⚠️ MongoDB not connected.")
            return
        total_logs = self.logs_collection.count_documents({})
        print(f"🔎 Re-evaluating {total_logs} logs from MongoDB...")
        cursor = self.logs_collection.find({})
        i = 0
        matches_found = 0
        for doc in cursor:
            i += 1
            try:
                for rule in self.sigma_rules:
                    if rule.matches(doc):
                        print(f"🚨 Historical match: {rule.title} on log {doc.get('_id')}")
                        self.save_alert_to_mongo(rule, doc)
                        matches_found += 1
                if i % 500 == 0:
                    print(f"  Processed {i} logs... Found {matches_found} matches so far.")
            except Exception as e:
                print(f"⚠️ Error evaluating MongoDB doc {doc.get('_id')}: {e}")
        print(f"✅ Re-evaluation complete. Found {matches_found} total matches.")

    # Event formatting (for terminal)
    def format_event(self, topic, event_data):
        winlog = event_data.get('winlog', {})
        event_id = winlog.get('event_id') or winlog.get('EventID') or event_data.get('event_id') or 'N/A'
        computer = (event_data.get('host') or {}).get('name') if isinstance(event_data.get('host'),
                                                                            dict) else event_data.get('host') or 'N/A'
        timestamp = event_data.get('@timestamp') or event_data.get('timestamp') or 'N/A'
        colors = {'application': '\033[93m', 'system': '\033[94m'}
        color = colors.get(topic, '\033[0m')
        reset = '\033[0m'

        try:
            eid_int = int(event_id)
        except Exception:
            eid_int = None

        event_descriptions = {
            4625: "🚨 FAILED LOGON",
            4624: "🔓 SUCCESSFUL LOGON",
            4634: "👋 ACCOUNT LOGOFF",
            4688: "🚀 PROCESS CREATED",
            4689: "❌ PROCESS TERMINATED",
            4720: "👤 USER ACCOUNT CREATED",
            4726: "🗑️ USER ACCOUNT DELETED",
            4740: "🔐 ACCOUNT LOCKED OUT",
            4776: "🔑 CREDENTIAL VALIDATION",
            4778: "🖥️ RDP SESSION RECONNECTED",
            4779: "🚪 RDP SESSION DISCONNECTED"
        }
        event_desc = event_descriptions.get(eid_int, "ℹ️ EVENT")

        return f"""{color}╔═══════════════════════════════════════════════════{reset}
{color}║ {event_desc} {reset}
{color}╠═══════════════════════════════════════════════════{reset}
{color}║ Topic: {topic.upper():15} Event ID: {event_id}{reset}
{color}║ Computer: {computer}{reset}
{color}║ Time: {timestamp}{reset}
{color}╚═══════════════════════════════════════════════════{reset}"""

    # Kafka consumption loop
    def consume_messages(self):
        if not self.connect():
            print("⚠️ Kafka connect failed, retrying in 5 seconds...")
            time.sleep(5)
            return self.consume_messages()

        self.running = True
        self.load_sigma_rules()

        print("🎯 Starting to consume Kafka events...\n")

        try:
            for message in self.consumer:
                try:
                    self.process_message(message)
                except Exception as e:
                    print(f"⚠️ Error processing message from Kafka: {e}")
                if not self.running:
                    break
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt - stopping consumer...")
        except Exception as e:
            print(f"❌ Unexpected consumer error: {e}")
        finally:
            self.stop()

    def process_message(self, message):
        try:
            event_data = message.value
            if event_data is None:
                return
            topic = message.topic
            normalized = self.normalize_event(topic, event_data)

            if normalized:
                self.save_to_mongo(normalized)
                self.save_normalized_to_file(normalized)

                # Rate limit console output
                self.processed_count += 1
                current_time = time.time()

                if self.processed_count % 10 == 0 or (current_time - self.last_log_time) > 30:
                    print(
                        f"📊 Processed {self.processed_count} events. Last: [{normalized.get('timestamp')}] {normalized.get('host')} {normalized.get('event_type')}")
                    print(self.format_event(topic, event_data))
                    self.last_log_time = current_time

                # 🔥 CRITICAL FIX: Evaluate Sigma rules for ALL events (not just security)
                self.evaluate_sigma_rules(normalized)

        except Exception as e:
            print(f"⚠️ Error processing message: {e}")

    def stop(self):
        self.running = False
        if self.consumer:
            try:
                self.consumer.close()
            except Exception as e:
                print(f"⚠️ Error closing Kafka consumer: {e}")
        if self.mongo_client:
            try:
                self.mongo_client.close()
                print("✅ MongoClient closed.")
            except Exception as e:
                print(f"⚠️ Error closing MongoClient: {e}")
        print(f"✅ Consumer stopped. Processed {self.processed_count} total events.")


# -------------------------
# Entry point
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="SIEM Kafka consumer with Sigma rule evaluation")
    parser.add_argument("--recheck", action="store_true", help="Load Sigma rules and re-evaluate all logs in MongoDB")
    parser.add_argument("--bootstrap", nargs='+', help="Kafka bootstrap servers (space-separated)")
    args = parser.parse_args()

    if args.bootstrap:
        bootstrap = args.bootstrap
    else:
        bootstrap = KAFKA_BOOTSTRAP

    consumer = SIEMKafkaConsumer(bootstrap_servers=bootstrap)

    if args.recheck:
        consumer.recheck_mongo_logs()
        consumer.stop()
        return

    # Start consuming live
    consumer.consume_messages()


if __name__ == "__main__":
    main()