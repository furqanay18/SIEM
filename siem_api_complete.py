#!/usr/bin/env python3
"""
siem_api_complete.py - Complete SIEM Backend with Authentication & Email Alerts
Version: 2.0
Features:
- JWT Authentication with role-based access control
- User management (Admin/Analyst roles)
- Email alerts for critical events
- All SIEM API endpoints (stats, logs, alerts, timeline, distributions)
- MongoDB integration
- CORS enabled for frontend
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING, ASCENDING
from datetime import datetime, timedelta
import sys
import jwt
import bcrypt
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import traceback

# ============================================
# Configuration
# ============================================
MONGO_URI = "mongodb+srv://qadrshah2_db_user:ZPaM7R7iPcWwmJvP@logtracks.0aqgjwm.mongodb.net/"
MONGO_DB = "logtracks_db"
LOGS_COLLECTION = "normalized_logs"
ALERTS_COLLECTION = "alerts"
USERS_COLLECTION = "users"
SECRET_KEY = "siem-secret-key-change-in-production-2024"  # Change this in production!

# Email configuration (Gmail example - configure before use)
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = "your-email@gmail.com"  # ⚠️ CONFIGURE THIS
EMAIL_PASSWORD = "your-app-password"  # ⚠️ CONFIGURE THIS (Gmail App Password)
EMAIL_FROM = "SIEM Alerts <your-email@gmail.com>"
EMAIL_ENABLED = False  # Set to True after configuring email

# ============================================
# Flask App Setup
# ============================================
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://localhost:3001"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"]
    }
})

# ============================================
# MongoDB Connection
# ============================================
try:
    print("🔄 Connecting to MongoDB Atlas...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    client.server_info()  # Force connection test
    db = client[MONGO_DB]
    logs_collection = db[LOGS_COLLECTION]
    alerts_collection = db[ALERTS_COLLECTION]
    users_collection = db[USERS_COLLECTION]
    
    # Create indexes for better performance (with error handling)
    try:
        users_collection.create_index([("email", ASCENDING)], unique=True, background=True)
    except Exception as e:
        if 'already exists' not in str(e).lower():
            print(f"⚠️  Warning creating users index: {e}")
    
    try:
        logs_collection.create_index([("timestamp", DESCENDING)], background=True)
    except Exception as e:
        if 'already exists' not in str(e).lower():
            print(f"⚠️  Warning creating logs index: {e}")
    
    try:
        alerts_collection.create_index([("detected_at", DESCENDING)], background=True)
    except Exception as e:
        if 'already exists' not in str(e).lower():
            print(f"⚠️  Warning creating alerts index: {e}")
    
    try:
        # Drop conflicting index if exists
        try:
            alerts_collection.drop_index("alert_id_1")
        except:
            pass
        # Create new index without sparse option
        alerts_collection.create_index([("alert_id", ASCENDING)], unique=True, background=True)
    except Exception as e:
        if 'already exists' not in str(e).lower() and 'IndexKeySpecsConflict' not in str(e):
            print(f"⚠️  Warning creating alert_id index: {e}")
    
    print("✅ Connected to MongoDB Atlas successfully!")
    print(f"   Database: {MONGO_DB}")
    print(f"   Collections: {LOGS_COLLECTION}, {ALERTS_COLLECTION}, {USERS_COLLECTION}")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    print("   Please check your MONGO_URI and internet connection")
    sys.exit(1)

# ============================================
# Authentication Decorators
# ============================================
def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format. Use: Bearer <token>'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            # Decode JWT token
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users_collection.find_one({"email": data['email']})
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token. Please login again.'}), 401
        except Exception as e:
            return jsonify({'error': f'Token validation failed: {str(e)}'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# ============================================
# Email Alert System
# ============================================
def send_email_alert(alert_data, recipient_email):
    """Send email notification for security alerts"""
    if not EMAIL_ENABLED:
        print(f"⚠️  Email alerts disabled. Configure EMAIL_USER and EMAIL_PASSWORD to enable.")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 SIEM Alert: {alert_data.get('rule_title', 'Security Event')}"
        msg['From'] = EMAIL_FROM
        msg['To'] = recipient_email
        
        # Get event details safely
        normalized_event = alert_data.get('normalized_event', {})
        host = normalized_event.get('host', 'N/A')
        event_id = normalized_event.get('event_id', 'N/A')
        source_ip = normalized_event.get('source_ip', 'N/A')
        
        # HTML email body
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; background-color: #1e293b; color: #e2e8f0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #334155; border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
              
              <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #ef4444; margin: 0; font-size: 28px;">🚨 Security Alert</h1>
                <p style="color: #94a3b8; margin-top: 5px;">SIEM Platform Detection</p>
              </div>
              
              <div style="background-color: #1e293b; padding: 20px; border-radius: 8px; border-left: 4px solid #ef4444;">
                <h2 style="color: #f1f5f9; margin-top: 0; font-size: 20px;">{alert_data.get('rule_title', 'Unknown Alert')}</h2>
                <p style="color: #cbd5e1; line-height: 1.6;">{alert_data.get('description', 'No description available')}</p>
              </div>
              
              <div style="margin-top: 25px; background-color: #1e293b; padding: 20px; border-radius: 8px;">
                <table style="width: 100%; border-collapse: collapse;">
                  <tr>
                    <td style="padding: 10px 0; color: #94a3b8; font-weight: bold;">Severity:</td>
                    <td style="padding: 10px 0; text-align: right;">
                      <span style="background-color: #ef4444; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 12px;">
                        {alert_data.get('level', 'N/A').upper()}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding: 10px 0; color: #94a3b8; font-weight: bold;">Detected At:</td>
                    <td style="padding: 10px 0; color: #f1f5f9; text-align: right;">{alert_data.get('detected_at', 'N/A')}</td>
                  </tr>
                  <tr>
                    <td style="padding: 10px 0; color: #94a3b8; font-weight: bold;">Host:</td>
                    <td style="padding: 10px 0; color: #f1f5f9; text-align: right;">{host}</td>
                  </tr>
                  <tr>
                    <td style="padding: 10px 0; color: #94a3b8; font-weight: bold;">Event ID:</td>
                    <td style="padding: 10px 0; color: #f1f5f9; text-align: right;">{event_id}</td>
                  </tr>
                  <tr>
                    <td style="padding: 10px 0; color: #94a3b8; font-weight: bold;">Source IP:</td>
                    <td style="padding: 10px 0; color: #f1f5f9; text-align: right;">{source_ip}</td>
                  </tr>
                </table>
              </div>
              
              <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #475569; text-align: center;">
                <p style="color: #94a3b8; font-size: 13px; margin: 5px 0;">
                  🛡️ This is an automated alert from your SIEM system
                </p>
                <p style="color: #64748b; font-size: 12px; margin: 5px 0;">
                  Please review this alert in your dashboard immediately
                </p>
                <div style="margin-top: 15px;">
                  <a href="http://localhost:3000" style="background-color: #8b5cf6; color: white; padding: 10px 25px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    View Dashboard
                  </a>
                </div>
              </div>
              
            </div>
          </body>
        </html>
        """
        
        part = MIMEText(html, 'html')
        msg.attach(part)
        
        # Send email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email alert sent to {recipient_email}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print(f"❌ Email authentication failed. Check EMAIL_USER and EMAIL_PASSWORD")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error sending email: {e}")
        return False
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

def notify_users_for_alert(alert_data):
    """Send email notifications to all eligible users based on their preferences"""
    try:
        severity = alert_data.get('level', 'medium').lower()
        
        # Find users who want notifications for this severity level
        query = {
            "email_alerts": True,
            f"notification_preferences.{severity}": True
        }
        
        users = users_collection.find(query)
        sent_count = 0
        
        for user in users:
            if send_email_alert(alert_data, user['email']):
                sent_count += 1
        
        if sent_count > 0:
            print(f"📧 Sent {sent_count} email notification(s) for alert: {alert_data.get('rule_title')}")
        
        return sent_count
    except Exception as e:
        print(f"⚠️  Error in notify_users_for_alert: {e}")
        return 0

# ============================================
# Authentication Endpoints
# ============================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        role = data.get('role', 'analyst')  # default role: analyst
        
        # Validation
        if not email or not password or not name:
            return jsonify({'error': 'Email, password, and name are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if role not in ['admin', 'analyst']:
            return jsonify({'error': 'Invalid role. Must be admin or analyst'}), 400
        
        # Check if user already exists
        if users_collection.find_one({"email": email}):
            return jsonify({'error': 'User with this email already exists'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user document
        user = {
            "email": email,
            "password": hashed_password,
            "name": name,
            "role": role,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "email_alerts": True,  # Enable email alerts by default
            "notification_preferences": {
                "critical": True,
                "high": True,
                "medium": False,
                "low": False
            }
        }
        
        users_collection.insert_one(user)
        
        print(f"✅ New user registered: {email} ({role})")
        
        return jsonify({
            'message': 'User registered successfully',
            'email': email,
            'name': name,
            'role': role
        }), 201
        
    except Exception as e:
        print(f"❌ Registration error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user and return JWT token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Update last login
        users_collection.update_one(
            {"email": email},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        # Generate JWT token (expires in 24 hours)
        token = jwt.encode({
            'email': email,
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")
        
        print(f"✅ User logged in: {email}")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'email': user['email'],
                'name': user['name'],
                'role': user['role']
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user information"""
    try:
        return jsonify({
            'email': current_user['email'],
            'name': current_user['name'],
            'role': current_user['role'],
            'email_alerts': current_user.get('email_alerts', True),
            'notification_preferences': current_user.get('notification_preferences', {
                'critical': True,
                'high': True,
                'medium': False,
                'low': False
            }),
            'created_at': current_user.get('created_at').isoformat() if current_user.get('created_at') else None,
            'last_login': current_user.get('last_login').isoformat() if current_user.get('last_login') else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# User Management Endpoints
# ============================================
@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    """Get all users (admin only)"""
    try:
        users = list(users_collection.find({}, {'password': 0}))  # Exclude password
        
        for user in users:
            user['_id'] = str(user['_id'])
            if user.get('created_at'):
                user['created_at'] = user['created_at'].isoformat()
            if user.get('last_login'):
                user['last_login'] = user['last_login'].isoformat()
        
        return jsonify({
            'users': users,
            'total': len(users)
        }), 200
        
    except Exception as e:
        print(f"❌ Error fetching users: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<email>/settings', methods=['PUT'])
@token_required
def update_user_settings(current_user, email):
    """Update user notification settings"""
    try:
        # Only allow users to update their own settings, or admins can update anyone
        if current_user['email'] != email and current_user.get('role') != 'admin':
            return jsonify({'error': 'Permission denied'}), 403
        
        data = request.get_json()
        update_fields = {}
        
        if 'email_alerts' in data:
            update_fields['email_alerts'] = bool(data['email_alerts'])
        
        if 'notification_preferences' in data:
            update_fields['notification_preferences'] = data['notification_preferences']
        
        if not update_fields:
            return jsonify({'error': 'No settings to update'}), 400
        
        result = users_collection.update_one(
            {"email": email},
            {"$set": update_fields}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        print(f"✅ Settings updated for user: {email}")
        
        return jsonify({'message': 'Settings updated successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error updating settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<email>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(current_user, email):
    """Delete user (admin only)"""
    try:
        # Prevent deleting yourself
        if current_user['email'] == email:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        result = users_collection.delete_one({"email": email})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        print(f"✅ User deleted: {email}")
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# SIEM Endpoints (Protected)
# ============================================
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint (public)"""
    try:
        # Test MongoDB connection
        client.server_info()
        
        # Get collection stats
        logs_count = logs_collection.count_documents({})
        alerts_count = alerts_collection.count_documents({})
        users_count = users_collection.count_documents({})
        
        return jsonify({
            "status": "healthy",
            "mongodb": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "database": MONGO_DB,
            "collections": {
                "logs": logs_count,
                "alerts": alerts_count,
                "users": users_count
            },
            "email_alerts": "enabled" if EMAIL_ENABLED else "disabled"
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Dashboard statistics"""
    try:
        time_range = request.args.get('range', '24h')
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Total logs count
        total_logs = logs_collection.count_documents({
            "timestamp": {"$gte": since_time.isoformat()}
        })
        
        # Critical alerts count
        critical_alerts = alerts_collection.count_documents({
            "level": "critical",
            "detected_at": {"$gte": since_time}
        })
        
        # Active hosts (unique count)
        hosts_pipeline = [
            {"$match": {"timestamp": {"$gte": since_time.isoformat()}}},
            {"$group": {"_id": "$host"}},
            {"$count": "total"}
        ]
        hosts_result = list(logs_collection.aggregate(hosts_pipeline))
        active_hosts = hosts_result[0]['total'] if hosts_result else 0
        
        # Events per minute (last hour average)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_events = logs_collection.count_documents({
            "timestamp": {"$gte": one_hour_ago.isoformat()}
        })
        events_per_min = round(recent_events / 60, 1) if recent_events > 0 else 0
        
        # Total threats (all alerts)
        total_threats = alerts_collection.count_documents({})
        
        # System uptime calculation (mock - replace with actual uptime logic)
        uptime_hours = 168  # Mock: 7 days uptime
        
        return jsonify({
            "totalLogs": total_logs,
            "criticalAlerts": critical_alerts,
            "activeHosts": active_hosts,
            "eventsPerMin": events_per_min,
            "totalThreats": total_threats,
            "systemUptime": f"{uptime_hours}h",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    """Get logs with filtering and pagination"""
    try:
        limit = int(request.args.get('limit', 100))
        skip = int(request.args.get('skip', 0))
        event_type = request.args.get('event_type', 'all')
        search = request.args.get('search', '')
        time_range = request.args.get('range', '24h')
        
        # Build time filter
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        query = {"timestamp": {"$gte": since_time.isoformat()}}
        
        # Event type filter
        if event_type != 'all':
            query['event_type'] = event_type
        
        # Search filter
        if search:
            query['$or'] = [
                {"message": {"$regex": search, "$options": "i"}},
                {"host": {"$regex": search, "$options": "i"}},
                {"source_ip": {"$regex": search, "$options": "i"}}
            ]
        
        # Execute query with pagination
        cursor = logs_collection.find(query).sort("timestamp", DESCENDING).skip(skip).limit(limit)
        logs = []
        
        for doc in cursor:
            doc['_id'] = str(doc['_id'])
            logs.append(doc)
        
        total = logs_collection.count_documents(query)
        
        return jsonify({
            "logs": logs,
            "total": total,
            "limit": limit,
            "skip": skip,
            "has_more": (skip + limit) < total
        }), 200
        
    except Exception as e:
        print(f"❌ Error fetching logs: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user):
    """Get alerts with filtering"""
    try:
        limit = int(request.args.get('limit', 50))
        severity = request.args.get('severity', 'all')
        time_range = request.args.get('range', '24h')
        status = request.args.get('status', 'all')
        
        # Build time filter
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        query = {"detected_at": {"$gte": since_time}}
        
        # Severity filter
        if severity != 'all':
            query['level'] = severity
        
        # Status filter
        if status != 'all':
            query['status'] = status
        
        # Execute query
        cursor = alerts_collection.find(query).sort("detected_at", DESCENDING).limit(limit)
        alerts = []
        
        for doc in cursor:
            doc['_id'] = str(doc['_id'])
            if isinstance(doc.get('detected_at'), datetime):
                doc['detected_at'] = doc['detected_at'].isoformat()
            alerts.append(doc)
        
        total = alerts_collection.count_documents(query)
        
        return jsonify({
            "alerts": alerts,
            "total": total
        }), 200
        
    except Exception as e:
        print(f"❌ Error fetching alerts: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts/<alert_id>/status', methods=['PUT'])
@token_required
def update_alert_status(current_user, alert_id):
    """Update alert status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        valid_statuses = ['new', 'in_progress', 'resolved', 'false_positive']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        result = alerts_collection.update_one(
            {"alert_id": alert_id},
            {
                "$set": {
                    "status": new_status,
                    "updated_by": current_user['email'],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Alert not found'}), 404
        
        print(f"✅ Alert {alert_id} status updated to {new_status} by {current_user['email']}")
        
        return jsonify({
            'message': 'Alert status updated successfully',
            'alert_id': alert_id,
            'new_status': new_status
        }), 200
        
    except Exception as e:
        print(f"❌ Error updating alert status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/distribution/events', methods=['GET'])
@token_required
def get_event_distribution(current_user):
    """Event type distribution"""
    try:
        time_range = request.args.get('range', '24h')
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": since_time.isoformat()}}},
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$project": {"name": "$_id", "value": "$count", "_id": 0}},
            {"$sort": {"value": -1}}
        ]
        
        result = list(logs_collection.aggregate(pipeline))
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Error getting event distribution: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/distribution/severity', methods=['GET'])
@token_required
def get_severity_distribution(current_user):
    """Alert severity distribution"""
    try:
        time_range = request.args.get('range', '24h')
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"detected_at": {"$gte": since_time}}},
            {"$group": {"_id": "$level", "count": {"$sum": 1}}},
            {"$project": {"name": "$_id", "value": "$count", "_id": 0}},
            {"$sort": {"value": -1}}
        ]
        
        result = list(alerts_collection.aggregate(pipeline))
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Error getting severity distribution: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/timeline', methods=['GET'])
@token_required
def get_timeline(current_user):
    """Time series data for events and alerts"""
    try:
        time_range = request.args.get('range', '1h')
        intervals = int(request.args.get('intervals', 12))
        
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        
        interval_minutes = (hours * 60) // intervals
        
        timeline = []
        for i in range(intervals):
            interval_start = datetime.utcnow() - timedelta(minutes=interval_minutes * (intervals - i))
            interval_end = datetime.utcnow() - timedelta(minutes=interval_minutes * (intervals - i - 1))
            
            # Count events in interval
            events_count = logs_collection.count_documents({
                "timestamp": {
                    "$gte": interval_start.isoformat(),
                    "$lt": interval_end.isoformat()
                }
            })
            
            # Count alerts in interval
            alerts_count = alerts_collection.count_documents({
                "detected_at": {
                    "$gte": interval_start,
                    "$lt": interval_end
                }
            })
            
            timeline.append({
                "time": interval_end.strftime("%H:%M"),
                "events": events_count,
                "alerts": alerts_count
            })
        
        return jsonify(timeline), 200
        
    except Exception as e:
        print(f"❌ Error getting timeline: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/hosts', methods=['GET'])
@token_required
def get_hosts(current_user):
    """Get list of active hosts"""
    try:
        time_range = request.args.get('range', '24h')
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": since_time.isoformat()}}},
            {"$group": {
                "_id": "$host",
                "event_count": {"$sum": 1},
                "last_seen": {"$max": "$timestamp"}
            }},
            {"$project": {
                "host": "$_id",
                "event_count": 1,
                "last_seen": 1,
                "_id": 0
            }},
            {"$sort": {"event_count": -1}},
            {"$limit": 100}
        ]
        
        result = list(logs_collection.aggregate(pipeline))
        return jsonify({
            "hosts": result,
            "total": len(result)
        }), 200
        
    except Exception as e:
        print(f"❌ Error getting hosts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/sources', methods=['GET'])
@token_required
def get_sources(current_user):
    """Get event sources distribution"""
    try:
        time_range = request.args.get('range', '24h')
        hours = int(time_range.replace('h', '').replace('d', ''))
        if 'd' in time_range:
            hours *= 24
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": since_time.isoformat()}}},
            {"$group": {
                "_id": {
                    "host": "$host",
                    "event_type": "$event_type"
                },
                "count": {"$sum": 1}
            }},
            {"$project": {
                "host": "$_id.host",
                "event_type": "$_id.event_type",
                "count": 1,
                "_id": 0
            }},
            {"$sort": {"count": -1}},
            {"$limit": 50}
        ]
        
        result = list(logs_collection.aggregate(pipeline))
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Error getting sources: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================
# Alert Notification Endpoints
# ============================================
@app.route('/api/alerts/notify', methods=['POST'])
@token_required
@admin_required
def trigger_alert_notification(current_user):
    """Manually trigger email notification for an alert (admin only)"""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({'error': 'alert_id is required'}), 400
        
        # Find the alert
        alert = alerts_collection.find_one({"alert_id": alert_id})
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Send notifications
        sent_count = notify_users_for_alert(alert)
        
        return jsonify({
            'message': f'Email notifications sent to {sent_count} user(s)',
            'alert_id': alert_id,
            'recipients': sent_count
        }), 200
        
    except Exception as e:
        print(f"❌ Error triggering notification: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/test-email', methods=['POST'])
@token_required
def test_email_alert(current_user):
    """Test email configuration by sending test alert"""
    try:
        # Create a mock alert for testing
        test_alert = {
            'rule_title': 'Test Alert - Email Configuration',
            'description': 'This is a test alert to verify your email configuration is working correctly.',
            'level': 'medium',
            'detected_at': datetime.utcnow().isoformat(),
            'normalized_event': {
                'host': 'test-server',
                'event_id': '9999',
                'source_ip': '192.168.1.100'
            }
        }
        
        # Send test email to current user
        success = send_email_alert(test_alert, current_user['email'])
        
        if success:
            return jsonify({
                'message': 'Test email sent successfully',
                'recipient': current_user['email']
            }), 200
        else:
            return jsonify({
                'error': 'Failed to send test email. Check email configuration.',
                'email_enabled': EMAIL_ENABLED
            }), 500
        
    except Exception as e:
        print(f"❌ Error sending test email: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# Search & Query Endpoints
# ============================================
@app.route('/api/search', methods=['GET'])
@token_required
def global_search(current_user):
    """Global search across logs and alerts"""
    try:
        query = request.args.get('q', '')
        limit = int(request.args.get('limit', 50))
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Search in logs
        logs_query = {
            '$or': [
                {"message": {"$regex": query, "$options": "i"}},
                {"host": {"$regex": query, "$options": "i"}},
                {"source_ip": {"$regex": query, "$options": "i"}},
                {"event_type": {"$regex": query, "$options": "i"}}
            ]
        }
        logs_results = list(logs_collection.find(logs_query).sort("timestamp", DESCENDING).limit(limit))
        
        for log in logs_results:
            log['_id'] = str(log['_id'])
        
        # Search in alerts
        alerts_query = {
            '$or': [
                {"rule_title": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}},
                {"normalized_event.host": {"$regex": query, "$options": "i"}}
            ]
        }
        alerts_results = list(alerts_collection.find(alerts_query).sort("detected_at", DESCENDING).limit(limit))
        
        for alert in alerts_results:
            alert['_id'] = str(alert['_id'])
            if isinstance(alert.get('detected_at'), datetime):
                alert['detected_at'] = alert['detected_at'].isoformat()
        
        return jsonify({
            'query': query,
            'logs': logs_results,
            'alerts': alerts_results,
            'total_logs': len(logs_results),
            'total_alerts': len(alerts_results)
        }), 200
        
    except Exception as e:
        print(f"❌ Error in global search: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================
# System Configuration Endpoints
# ============================================
@app.route('/api/config', methods=['GET'])
@token_required
@admin_required
def get_config(current_user):
    """Get system configuration (admin only)"""
    try:
        config = {
            'email_enabled': EMAIL_ENABLED,
            'email_host': EMAIL_HOST,
            'email_port': EMAIL_PORT,
            'email_from': EMAIL_FROM,
            'mongodb_uri': MONGO_URI.split('@')[1] if '@' in MONGO_URI else 'configured',
            'database': MONGO_DB,
            'collections': {
                'logs': LOGS_COLLECTION,
                'alerts': ALERTS_COLLECTION,
                'users': USERS_COLLECTION
            },
            'jwt_expiry': '24 hours'
        }
        return jsonify(config), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# Error Handlers
# ============================================
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'message': 'The HTTP method is not allowed for this endpoint'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# ============================================
# Startup & Initialization
# ============================================
def create_default_admin():
    """Create default admin user if it doesn't exist"""
    try:
        admin_email = "admin@siem.local"
        
        # Check if admin already exists
        if users_collection.find_one({"email": admin_email}):
            print(f"ℹ️  Admin user already exists: {admin_email}")
            return
        
        # Create default admin
        hashed_pw = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        admin_user = {
            "email": admin_email,
            "password": hashed_pw,
            "name": "System Administrator",
            "role": "admin",
            "created_at": datetime.utcnow(),
            "last_login": None,
            "email_alerts": True,
            "notification_preferences": {
                "critical": True,
                "high": True,
                "medium": True,
                "low": False
            }
        }
        
        users_collection.insert_one(admin_user)
        
        print("\n" + "="*60)
        print("✅ Default admin user created:")
        print(f"   📧 Email: {admin_email}")
        print("   🔑 Password: admin123")
        print("   ⚠️  IMPORTANT: Change this password after first login!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"⚠️  Could not create default admin: {e}")

def check_email_config():
    """Check if email is properly configured"""
    global EMAIL_ENABLED
    
    if EMAIL_USER == "your-email@gmail.com" or EMAIL_PASSWORD == "your-app-password":
        print("\n" + "="*60)
        print("⚠️  EMAIL ALERTS NOT CONFIGURED")
        print("="*60)
        print("To enable email alerts:")
        print("1. Edit siem_api_complete.py")
        print("2. Update EMAIL_USER with your Gmail address")
        print("3. Update EMAIL_PASSWORD with your Gmail App Password")
        print("4. Set EMAIL_ENABLED = True")
        print("\nFor Gmail App Password:")
        print("- Go to: https://myaccount.google.com/apppasswords")
        print("- Generate a new App Password for 'Mail'")
        print("="*60 + "\n")
        EMAIL_ENABLED = False
    else:
        EMAIL_ENABLED = True
        print(f"✅ Email alerts configured: {EMAIL_USER}")

# ============================================
# Main Entry Point
# ============================================
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 SIEM Complete API Server Starting...")
    print("="*60)
    print(f"📊 MongoDB Database: {MONGO_DB}")
    print(f"🔐 Authentication: JWT-based (24h expiry)")
    print(f"📧 Email Alerts: {'Enabled' if EMAIL_ENABLED else 'Disabled (needs configuration)'}")
    print("="*60)
    
    # Create default admin user
    create_default_admin()
    
    # Check email configuration
    check_email_config()
    
    print("\n📡 Available API Endpoints:")
    print("   Authentication:")
    print("     POST   /api/auth/register")
    print("     POST   /api/auth/login")
    print("     GET    /api/auth/me")
    print("\n   SIEM Operations:")
    print("     GET    /api/health")
    print("     GET    /api/stats")
    print("     GET    /api/logs")
    print("     GET    /api/alerts")
    print("     PUT    /api/alerts/<id>/status")
    print("     GET    /api/timeline")
    print("     GET    /api/distribution/events")
    print("     GET    /api/distribution/severity")
    print("     GET    /api/hosts")
    print("     GET    /api/sources")
    print("     GET    /api/search")
    print("\n   User Management:")
    print("     GET    /api/users (admin)")
    print("     PUT    /api/users/<email>/settings")
    print("     DELETE /api/users/<email> (admin)")
    print("\n   Alerts:")
    print("     POST   /api/alerts/notify (admin)")
    print("     POST   /api/alerts/test-email")
    print("\n   System:")
    print("     GET    /api/config (admin)")
    print("="*60)
    print(f"\n🌐 Server running on: http://0.0.0.0:5000")
    print(f"🔗 Frontend should connect to: http://localhost:5000/api")
    print("\n💡 Quick Start:")
    print(f"   1. Start frontend: cd siem-dashboard && npm start")
    print(f"   2. Open browser: http://localhost:3000")
    print(f"   3. Login with: admin@siem.local / admin123")
    print("="*60 + "\n")
    
    # Run Flask app
    try:
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down SIEM API server...")
        print("✅ Server stopped gracefully")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        traceback.print_exc()