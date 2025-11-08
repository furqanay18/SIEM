#!/usr/bin/env python3
"""
siem_enhanced_features.py - Additional Enhanced Modules
This file adds:
- Alert Streaming with WebSocket
- Advanced Correlation Rules Engine
- Optimized Storage with Indexing
- Enhanced Search with ElasticSearch-like features
- Real-time Dashboard Updates

Add this to siem_api_complete.py or run as separate service
"""

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING, ASCENDING, TEXT
from datetime import datetime, timedelta
from threading import Thread
import time
import json
import re
from collections import defaultdict, deque

# ============================================
# Configuration
# ============================================
MONGO_URI = "mongodb+srv://qadrshah2_db_user:ZPaM7R7iPcWwmJvP@logtracks.0aqgjwm.mongodb.net/"
MONGO_DB = "logtracks_db"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem-socketio-secret'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
logs_collection = db["normalized_logs"]
alerts_collection = db["alerts"]
correlation_rules_collection = db["correlation_rules"]
dashboard_cache_collection = db["dashboard_cache"]

# ============================================
# 1. OPTIMIZED STORAGE AND SEARCHING
# ============================================

class OptimizedStorage:
    """Enhanced storage with indexing and caching"""
    
    @staticmethod
    def create_optimized_indexes():
        """Create comprehensive indexes for faster queries"""
        try:
            print("🔧 Creating optimized indexes...")
            
            # Helper function to safely create index
            def safe_create_index(collection, keys, **kwargs):
                try:
                    collection.create_index(keys, **kwargs)
                except Exception as e:
                    if 'already exists' not in str(e).lower() and 'IndexKeySpecsConflict' not in str(e):
                        print(f"⚠️  Warning: {e}")
            
            # Logs collection indexes
            safe_create_index(logs_collection, [("timestamp", DESCENDING)], background=True)
            safe_create_index(logs_collection, [("host", ASCENDING)], background=True)
            safe_create_index(logs_collection, [("event_type", ASCENDING)], background=True)
            safe_create_index(logs_collection, [("event_id", ASCENDING)], background=True)
            safe_create_index(logs_collection, [("source_ip", ASCENDING)], background=True)
            safe_create_index(logs_collection, [
                ("timestamp", DESCENDING),
                ("event_type", ASCENDING)
            ], background=True)
            
            # Text index for full-text search
            try:
                # Check if text index already exists
                existing_indexes = logs_collection.list_indexes()
                text_index_exists = any(idx.get('name') == 'text_search_idx' for idx in existing_indexes)
                
                if not text_index_exists:
                    logs_collection.create_index([
                        ("message", TEXT),
                        ("host", TEXT)
                    ], background=True, name="text_search_idx")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    print(f"⚠️  Text index warning: {e}")
            
            # Alerts collection indexes
            safe_create_index(alerts_collection, [("detected_at", DESCENDING)], background=True)
            safe_create_index(alerts_collection, [("level", ASCENDING)], background=True)
            safe_create_index(alerts_collection, [("status", ASCENDING)], background=True)
            safe_create_index(alerts_collection, [
                ("level", ASCENDING),
                ("detected_at", DESCENDING)
            ], background=True)
            
            # Correlation rules indexes
            safe_create_index(correlation_rules_collection, [("enabled", ASCENDING)], background=True)
            safe_create_index(correlation_rules_collection, [("rule_name", ASCENDING)], unique=True, background=True)
            
            print("✅ Optimized indexes created successfully!")
            return True
        except Exception as e:
            print(f"❌ Error creating indexes: {e}")
            return False
    
    @staticmethod
    def cache_dashboard_stats():
        """Cache frequently accessed dashboard statistics"""
        try:
            stats = {
                "total_logs_24h": logs_collection.count_documents({
                    "timestamp": {"$gte": (datetime.utcnow() - timedelta(hours=24)).isoformat()}
                }),
                "critical_alerts": alerts_collection.count_documents({"level": "critical"}),
                "total_hosts": len(logs_collection.distinct("host")),
                "cached_at": datetime.utcnow()
            }
            
            dashboard_cache_collection.replace_one(
                {"_id": "main_stats"},
                {**stats, "_id": "main_stats"},
                upsert=True
            )
            return stats
        except Exception as e:
            print(f"Error caching stats: {e}")
            return None
    
    @staticmethod
    def advanced_search(query, filters=None):
        """Advanced search with multiple filters and relevance scoring"""
        try:
            # Build query
            search_query = {}
            
            # Text search
            if query:
                search_query["$text"] = {"$search": query}
            
            # Apply filters
            if filters:
                if filters.get('start_date'):
                    search_query["timestamp"] = {"$gte": filters['start_date']}
                if filters.get('end_date'):
                    if "timestamp" in search_query:
                        search_query["timestamp"]["$lte"] = filters['end_date']
                    else:
                        search_query["timestamp"] = {"$lte": filters['end_date']}
                if filters.get('event_type'):
                    search_query["event_type"] = filters['event_type']
                if filters.get('host'):
                    search_query["host"] = {"$regex": filters['host'], "$options": "i"}
            
            # Execute search with text score for relevance
            if query:
                cursor = logs_collection.find(
                    search_query,
                    {"score": {"$meta": "textScore"}}
                ).sort([("score", {"$meta": "textScore"})]).limit(100)
            else:
                cursor = logs_collection.find(search_query).sort("timestamp", DESCENDING).limit(100)
            
            results = []
            for doc in cursor:
                doc['_id'] = str(doc['_id'])
                results.append(doc)
            
            return results
        except Exception as e:
            print(f"Search error: {e}")
            return []
    
    @staticmethod
    def aggregate_by_time_window(collection, time_window_minutes=5, hours_back=24):
        """Aggregate data by time windows for efficient timeline queries"""
        try:
            since_time = datetime.utcnow() - timedelta(hours=hours_back)
            
            pipeline = [
                {"$match": {"timestamp": {"$gte": since_time.isoformat()}}},
                {"$addFields": {
                    "timestamp_dt": {"$dateFromString": {"dateString": "$timestamp"}}
                }},
                {"$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d %H:%M",
                            "date": {
                                "$dateTrunc": {
                                    "date": "$timestamp_dt",
                                    "unit": "minute",
                                    "binSize": time_window_minutes
                                }
                            }
                        }
                    },
                    "count": {"$sum": 1}
                }},
                {"$sort": {"_id": 1}}
            ]
            
            result = list(collection.aggregate(pipeline))
            return result
        except Exception as e:
            print(f"Aggregation error: {e}")
            return []

# ============================================
# 2. CORRELATION RULES ENGINE
# ============================================

class CorrelationEngine:
    """Advanced correlation rules engine for threat detection"""
    
    def __init__(self):
        self.rules = []
        self.event_buffer = defaultdict(lambda: deque(maxlen=1000))
        self.load_rules()
    
    def load_rules(self):
        """Load correlation rules from database"""
        try:
            rules = list(correlation_rules_collection.find({"enabled": True}))
            self.rules = rules
            print(f"✅ Loaded {len(rules)} correlation rules")
        except Exception as e:
            print(f"Error loading rules: {e}")
    
    def create_default_rules(self):
        """Create default correlation rules"""
        default_rules = [
            {
                "rule_name": "Multiple Failed Logins",
                "description": "Detect multiple failed login attempts from same source",
                "enabled": True,
                "severity": "high",
                "conditions": {
                    "event_type": "security",
                    "event_id": 4625,
                    "time_window": 300,  # 5 minutes
                    "threshold": 5
                },
                "action": "create_alert",
                "created_at": datetime.utcnow()
            },
            {
                "rule_name": "Rapid Process Creation",
                "description": "Detect rapid process creation (possible malware)",
                "enabled": True,
                "severity": "critical",
                "conditions": {
                    "event_type": "system",
                    "event_id": 4688,
                    "time_window": 60,  # 1 minute
                    "threshold": 10
                },
                "action": "create_alert",
                "created_at": datetime.utcnow()
            },
            {
                "rule_name": "Privilege Escalation Attempt",
                "description": "Detect potential privilege escalation",
                "enabled": True,
                "severity": "critical",
                "conditions": {
                    "event_id": [4672, 4673, 4674],
                    "time_window": 120,
                    "threshold": 3
                },
                "action": "create_alert",
                "created_at": datetime.utcnow()
            },
            {
                "rule_name": "Lateral Movement Detection",
                "description": "Detect lateral movement across hosts",
                "enabled": True,
                "severity": "high",
                "conditions": {
                    "event_id": [4624, 4648],
                    "unique_hosts": 3,
                    "time_window": 600,  # 10 minutes
                    "same_user": True
                },
                "action": "create_alert",
                "created_at": datetime.utcnow()
            },
            {
                "rule_name": "Data Exfiltration Pattern",
                "description": "Large data transfer detected",
                "enabled": True,
                "severity": "critical",
                "conditions": {
                    "event_type": "network",
                    "data_size_mb": 100,
                    "time_window": 300
                },
                "action": "create_alert",
                "created_at": datetime.utcnow()
            }
        ]
        
        for rule in default_rules:
            try:
                correlation_rules_collection.update_one(
                    {"rule_name": rule["rule_name"]},
                    {"$setOnInsert": rule},
                    upsert=True
                )
            except Exception as e:
                print(f"Error creating rule {rule['rule_name']}: {e}")
        
        print(f"✅ Created {len(default_rules)} default correlation rules")
    
    def evaluate_event(self, event):
        """Evaluate an event against all correlation rules"""
        alerts_generated = []
        
        for rule in self.rules:
            try:
                if self._matches_rule(event, rule):
                    alert = self._create_correlation_alert(event, rule)
                    if alert:
                        alerts_generated.append(alert)
            except Exception as e:
                print(f"Error evaluating rule {rule.get('rule_name')}: {e}")
        
        return alerts_generated
    
    def _matches_rule(self, event, rule):
        """Check if event matches rule conditions"""
        conditions = rule.get('conditions', {})
        
        # Check event type
        if 'event_type' in conditions:
            if event.get('event_type') != conditions['event_type']:
                return False
        
        # Check event ID
        if 'event_id' in conditions:
            event_ids = conditions['event_id']
            if isinstance(event_ids, list):
                if event.get('event_id') not in event_ids:
                    return False
            else:
                if event.get('event_id') != event_ids:
                    return False
        
        # Add to buffer for time-based analysis
        rule_name = rule.get('rule_name')
        self.event_buffer[rule_name].append({
            'event': event,
            'timestamp': datetime.utcnow()
        })
        
        # Check threshold within time window
        if 'threshold' in conditions and 'time_window' in conditions:
            time_window = timedelta(seconds=conditions['time_window'])
            cutoff_time = datetime.utcnow() - time_window
            
            # Count matching events in time window
            matching_events = [
                e for e in self.event_buffer[rule_name]
                if e['timestamp'] >= cutoff_time
            ]
            
            if len(matching_events) >= conditions['threshold']:
                # Clear buffer after triggering
                self.event_buffer[rule_name].clear()
                return True
        
        return False
    
    def _create_correlation_alert(self, event, rule):
        """Create alert from correlation rule match"""
        try:
            alert = {
                "alert_id": f"corr_{rule['rule_name']}_{int(time.time())}",
                "rule_title": rule['rule_name'],
                "description": rule['description'],
                "level": rule['severity'],
                "type": "correlation",
                "detected_at": datetime.utcnow(),
                "status": "new",
                "normalized_event": event,
                "correlation_rule_id": str(rule.get('_id'))
            }
            
            # Save to alerts collection
            alerts_collection.insert_one(alert)
            print(f"🚨 Correlation alert created: {rule['rule_name']}")
            
            return alert
        except Exception as e:
            print(f"Error creating correlation alert: {e}")
            return None

# ============================================
# 3. ALERT STREAMING WITH WEBSOCKET
# ============================================

class AlertStreamer:
    """Real-time alert streaming via WebSocket"""
    
    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
        self.active_connections = set()
        self.last_alert_id = None
        self.running = False
    
    def start_streaming(self):
        """Start background thread for alert streaming"""
        self.running = True
        thread = Thread(target=self._stream_alerts)
        thread.daemon = True
        thread.start()
        print("✅ Alert streaming started")
    
    def _stream_alerts(self):
        """Background task to stream new alerts"""
        while self.running:
            try:
                # Find new alerts
                query = {}
                if self.last_alert_id:
                    query = {"_id": {"$gt": self.last_alert_id}}
                
                new_alerts = list(alerts_collection.find(query).sort("detected_at", DESCENDING).limit(10))
                
                if new_alerts:
                    for alert in new_alerts:
                        self.last_alert_id = alert['_id']
                        alert['_id'] = str(alert['_id'])
                        if isinstance(alert.get('detected_at'), datetime):
                            alert['detected_at'] = alert['detected_at'].isoformat()
                        
                        # Emit to all connected clients
                        self.socketio.emit('new_alert', alert, namespace='/alerts')
                        print(f"📡 Streamed alert: {alert.get('rule_title')}")
                
                time.sleep(3)  # Check every 3 seconds
            except Exception as e:
                print(f"Error streaming alerts: {e}")
                time.sleep(5)
    
    def stop_streaming(self):
        """Stop alert streaming"""
        self.running = False

# ============================================
# 4. ENHANCED DASHBOARD MODULE
# ============================================

class EnhancedDashboard:
    """Enhanced dashboard with real-time metrics"""
    
    @staticmethod
    def get_real_time_metrics():
        """Get real-time dashboard metrics"""
        try:
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            
            metrics = {
                # Events per second (last 5 minutes)
                "events_per_second": EnhancedDashboard._calculate_eps(),
                
                # Alert rate (alerts per hour)
                "alerts_per_hour": alerts_collection.count_documents({
                    "detected_at": {"$gte": one_hour_ago}
                }),
                
                # Top talkers (most active hosts)
                "top_hosts": EnhancedDashboard._get_top_hosts(limit=5),
                
                # Top event types
                "top_event_types": EnhancedDashboard._get_top_event_types(limit=5),
                
                # Recent critical alerts
                "recent_critical": list(alerts_collection.find({
                    "level": "critical"
                }).sort("detected_at", DESCENDING).limit(5)),
                
                # System health
                "system_health": EnhancedDashboard._get_system_health(),
                
                # Threat score (0-100)
                "threat_score": EnhancedDashboard._calculate_threat_score(),
                
                "timestamp": now.isoformat()
            }
            
            # Clean up ObjectIds
            for alert in metrics["recent_critical"]:
                alert['_id'] = str(alert['_id'])
                if isinstance(alert.get('detected_at'), datetime):
                    alert['detected_at'] = alert['detected_at'].isoformat()
            
            return metrics
        except Exception as e:
            print(f"Error getting metrics: {e}")
            return {}
    
    @staticmethod
    def _calculate_eps():
        """Calculate events per second"""
        try:
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)
            count = logs_collection.count_documents({
                "timestamp": {"$gte": five_min_ago.isoformat()}
            })
            return round(count / 300, 2)  # 300 seconds = 5 minutes
        except:
            return 0
    
    @staticmethod
    def _get_top_hosts(limit=5):
        """Get most active hosts"""
        try:
            pipeline = [
                {"$group": {"_id": "$host", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": limit},
                {"$project": {"host": "$_id", "count": 1, "_id": 0}}
            ]
            return list(logs_collection.aggregate(pipeline))
        except:
            return []
    
    @staticmethod
    def _get_top_event_types(limit=5):
        """Get most common event types"""
        try:
            pipeline = [
                {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": limit},
                {"$project": {"type": "$_id", "count": 1, "_id": 0}}
            ]
            return list(logs_collection.aggregate(pipeline))
        except:
            return []
    
    @staticmethod
    def _get_system_health():
        """Calculate system health status"""
        try:
            critical_count = alerts_collection.count_documents({"level": "critical", "status": "new"})
            high_count = alerts_collection.count_documents({"level": "high", "status": "new"})
            
            if critical_count > 5:
                return {"status": "critical", "message": "Multiple critical alerts"}
            elif critical_count > 0:
                return {"status": "warning", "message": "Critical alerts present"}
            elif high_count > 10:
                return {"status": "warning", "message": "High number of alerts"}
            else:
                return {"status": "healthy", "message": "System operating normally"}
        except:
            return {"status": "unknown", "message": "Unable to determine"}
    
    @staticmethod
    def _calculate_threat_score():
        """Calculate overall threat score (0-100)"""
        try:
            # Weight different factors
            critical_alerts = alerts_collection.count_documents({"level": "critical"}) * 20
            high_alerts = alerts_collection.count_documents({"level": "high"}) * 10
            medium_alerts = alerts_collection.count_documents({"level": "medium"}) * 5
            
            score = min(critical_alerts + high_alerts + medium_alerts, 100)
            return score
        except:
            return 0

# ============================================
# WEBSOCKET ENDPOINTS
# ============================================

@socketio.on('connect', namespace='/alerts')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected to alerts stream')
    emit('connected', {'message': 'Connected to alert stream'})

@socketio.on('disconnect', namespace='/alerts')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected from alerts stream')

@socketio.on('subscribe', namespace='/alerts')
def handle_subscribe(data):
    """Subscribe to specific alert types"""
    severity = data.get('severity', 'all')
    join_room(f'alerts_{severity}')
    emit('subscribed', {'severity': severity})

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/api/enhanced/search', methods=['POST'])
def enhanced_search():
    """Advanced search endpoint"""
    try:
        data = request.get_json()
        query = data.get('query', '')
        filters = data.get('filters', {})
        
        storage = OptimizedStorage()
        results = storage.advanced_search(query, filters)
        
        return jsonify({
            'results': results,
            'total': len(results),
            'query': query
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/dashboard', methods=['GET'])
def enhanced_dashboard():
    """Enhanced dashboard metrics"""
    try:
        dashboard = EnhancedDashboard()
        metrics = dashboard.get_real_time_metrics()
        return jsonify(metrics), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/correlation-rules', methods=['GET'])
def get_correlation_rules():
    """Get all correlation rules"""
    try:
        rules = list(correlation_rules_collection.find({}))
        for rule in rules:
            rule['_id'] = str(rule['_id'])
            if isinstance(rule.get('created_at'), datetime):
                rule['created_at'] = rule['created_at'].isoformat()
        
        return jsonify({'rules': rules, 'total': len(rules)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/correlation-rules', methods=['POST'])
def create_correlation_rule():
    """Create new correlation rule"""
    try:
        data = request.get_json()
        
        rule = {
            "rule_name": data.get('rule_name'),
            "description": data.get('description'),
            "enabled": data.get('enabled', True),
            "severity": data.get('severity', 'medium'),
            "conditions": data.get('conditions', {}),
            "action": data.get('action', 'create_alert'),
            "created_at": datetime.utcnow()
        }
        
        result = correlation_rules_collection.insert_one(rule)
        rule['_id'] = str(result.inserted_id)
        
        return jsonify({'message': 'Rule created', 'rule': rule}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/correlation-rules/<rule_name>/toggle', methods=['PUT'])
def toggle_correlation_rule(rule_name):
    """Enable/disable correlation rule"""
    try:
        rule = correlation_rules_collection.find_one({"rule_name": rule_name})
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        new_status = not rule.get('enabled', False)
        correlation_rules_collection.update_one(
            {"rule_name": rule_name},
            {"$set": {"enabled": new_status}}
        )
        
        return jsonify({
            'message': 'Rule updated',
            'rule_name': rule_name,
            'enabled': new_status
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced/optimize-storage', methods=['POST'])
def optimize_storage():
    """Trigger storage optimization"""
    try:
        storage = OptimizedStorage()
        success = storage.create_optimized_indexes()
        storage.cache_dashboard_stats()
        
        return jsonify({
            'message': 'Storage optimization complete',
            'success': success
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# INITIALIZATION
# ============================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 SIEM Enhanced Features Server")
    print("="*60)
    
    # Initialize storage optimization
    print("\n📊 Initializing optimized storage...")
    storage = OptimizedStorage()
    storage.create_optimized_indexes()
    storage.cache_dashboard_stats()
    
    # Initialize correlation engine
    print("\n🔗 Initializing correlation engine...")
    engine = CorrelationEngine()
    engine.create_default_rules()
    
    # Initialize alert streamer
    print("\n📡 Initializing alert streaming...")
    streamer = AlertStreamer(socketio)
    streamer.start_streaming()
    
    print("\n✅ All enhanced features initialized!")
    print("="*60)
    print("\n📡 Enhanced Endpoints:")
    print("   POST   /api/enhanced/search")
    print("   GET    /api/enhanced/dashboard")
    print("   GET    /api/enhanced/correlation-rules")
    print("   POST   /api/enhanced/correlation-rules")
    print("   PUT    /api/enhanced/correlation-rules/<name>/toggle")
    print("   POST   /api/enhanced/optimize-storage")
    print("\n🔌 WebSocket: ws://localhost:5001/alerts")
    print("="*60 + "\n")
    
    # Run with SocketIO
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)