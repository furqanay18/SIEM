#!/usr/bin/env python3
"""
read_mongo_logs.py — Enhanced CLI SIEM Tool
===========================================
Displays MongoDB logs (normalized_logs) with colors and rich formatting.
Shows past 2 days of logs, then streams new ones in real time.
"""

from pymongo import MongoClient
from datetime import datetime, timedelta
import time
import sys
import os

# MongoDB connection settings
MONGO_URI = "mongodb+srv://qadrshah2_db_user:ZPaM7R7iPcWwmJvP@logtracks.0aqgjwm.mongodb.net/"
DB_NAME = "logtracks_db"
COLLECTION_NAME = "normalized_logs"

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header():
    clear_screen()
    print(f"""{BOLD}{CYAN}
███████╗██╗███████╗███╗   ███╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝██║██╔════╝████╗ ████║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗██║█████╗  ██╔████╔██║       ██║   ██║   ██║██║   ██║██║     
╚════██║██║██╔══╝  ██║╚██╔╝██║       ██║   ██║   ██║██║   ██║██║     
███████║██║███████╗██║ ╚═╝ ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝╚═╝╚══════╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{RESET}{BOLD}                   CLI SIEM TOOL v1.0{RESET}
─────────────────────────────────────────────────────────────
""")

def connect_mongo():
    """Connect to MongoDB and return collection handle."""
    try:
        client = MongoClient(MONGO_URI, connectTimeoutMS=20000, socketTimeoutMS=20000)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        print(f"{GREEN}✅ Connected to SIEM Tool successfully.{RESET}\n")
        return collection
    except Exception as e:
        print(f"{RED}❌ Failed to connect to SIEM tool.Make sure service is Running on your targeted device: {e}{RESET}")
        sys.exit(1)


def pretty_print_log(log):
    """Beautifully format a log entry for CLI output."""
    ts = log.get("timestamp") or datetime.utcnow().isoformat()
    host = log.get("host", "unknown")
    event_type = log.get("event_type", "unknown").upper()
    message = log.get("message", "").strip()
    source_ip = log.get("source_ip", "N/A")
    event_id = log.get("event_id", "N/A")
    alerts = log.get("alerts", [])

    # Pick color based on event type
    styles = {
        "SECURITY": (RED, "🛡️ "),
        "APPLICATION": (YELLOW, "⚙️ "),
        "SYSTEM": (BLUE, "🖥️ "),
        "NETWORK": (MAGENTA, "🌐 "),
        "UNKNOWN": (GRAY, "❓ "),
    }
    color, icon = styles.get(event_type, (GRAY, "📄 "))

    # Determine alert indicator
    alert_text = ""
    if alerts:
        alert_text = f"{RED}⚠️  {len(alerts)} Alert(s) Triggered!{RESET}"
        for a in alerts:
            alert_text += f"\n    {RED}- {a.get('rule_title', 'Unknown')} ({a.get('level', 'info')}){RESET}"
    else:
        alert_text = f"{GREEN}✅ No Alerts{RESET}"

    # Print formatted log box
    print(f"""{color}
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ {icon}{event_type:<12} | Host: {host}
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 🕒 Time:     {ts}
┃ 🧾 Event ID: {event_id}
┃ 🌐 Source IP:{source_ip}
┃ 📝 Message:  {message[:300]}{"..." if len(message) > 300 else ""}
┃ 🚨 Alerts:   {alert_text}
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
""")


def show_recent_logs(collection, days=2):
    """Show last N days of logs first."""
    since_time = datetime.utcnow() - timedelta(days=days)
    print(f"{CYAN}📜 Loading logs from the last {days} day(s)...{RESET}\n")

    cursor = collection.find({"timestamp": {"$gte": since_time.isoformat()}}).sort("timestamp", 1)
    count = 0
    for doc in cursor:
        pretty_print_log(doc)
        count += 1

    if count == 0:
        print(f"{YELLOW}⚠️  No logs found from the last {days} days.{RESET}\n")
    else:
        print(f"{GREEN}✅ Displayed {count} recent logs.{RESET}\n")


def tail_mongo_logs(collection):
    """Then keep streaming new ones in real-time."""
    print(f"{BOLD}🎯 Now waiting for new logs... (Ctrl+C to stop){RESET}\n")
    try:
        with collection.watch([{"$match": {"operationType": "insert"}}]) as stream:
            for change in stream:
                pretty_print_log(change["fullDocument"])
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 Stopped by user.{RESET}")
    except Exception as e:
        print(f"{RED}⚠️ Change stream error: {e}{RESET}")
        print(f"{YELLOW}Switching to polling mode...{RESET}\n")
        poll_mongo_logs(collection)


def poll_mongo_logs(collection, interval=5):
    """Fallback polling for environments where change streams aren't supported."""
    print(f"{CYAN}⏱️ Polling  every {interval}s for new logs...{RESET}\n")
    last_id = None
    try:
        while True:
            query = {"_id": {"$gt": last_id}} if last_id else {}
            cursor = collection.find(query).sort("_id", 1)
            for doc in cursor:
                pretty_print_log(doc)
                last_id = doc["_id"]
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 Stopped by user.{RESET}")
    except Exception as e:
        print(f"{RED}❌ Polling error: {e}{RESET}")


def main():
    print_header()
    coll = connect_mongo()
    show_recent_logs(coll, days=2)
    tail_mongo_logs(coll)


if __name__ == "__main__":
    main()
