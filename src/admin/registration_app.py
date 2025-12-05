"""
Bio-ISAC Self-Service Registration Web Application

A Flask web app that allows users to request access to the Bio-ISAC bot.
Administrators can review, approve, or deny requests through an admin dashboard.

Features:
- Public registration form for users to request access
- Admin dashboard to view and manage requests
- Automatic Heroku config var updates on approval
- Slack notifications for new requests and approvals

Environment Variables:
    SLACK_BOT_TOKEN     - For Slack notifications and user lookup
    HEROKU_API_KEY      - For automatic config var updates
    HEROKU_APP_NAME     - Target Heroku app
    ADMIN_SECRET_KEY    - Secret key for admin dashboard access
    DATABASE_URL or JAWSDB_URL - Database connection
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
import requests

# Import database connection from existing queries module
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.etl.queries import get_connection


def load_env() -> None:
    """Load environment variables from .env file if present."""
    if os.environ.get("ENV_READY"):
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        pass
    else:
        env_path = Path(__file__).resolve().parents[2] / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    os.environ["ENV_READY"] = "1"


load_env()

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", secrets.token_hex(32))

# Admin credentials (set ADMIN_PASSWORD in environment)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "bioisac-admin-2024")


# =============================================================================
# Database Operations
# =============================================================================

def create_request(full_name: str, email: str, organization: str, slack_id: str, reason: str) -> int:
    """Create a new access request."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_requests (full_name, email, organization, slack_id, reason)
            VALUES (%s, %s, %s, %s, %s)
        """, (full_name, email, organization, slack_id, reason))
        conn.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        conn.close()


def get_pending_requests() -> List[Dict]:
    """Get all pending access requests."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM user_requests 
            WHERE status = 'pending' 
            ORDER BY requested_at DESC
        """)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_all_requests() -> List[Dict]:
    """Get all access requests."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM user_requests 
            ORDER BY requested_at DESC
        """)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_request_by_id(request_id: int) -> Optional[Dict]:
    """Get a specific request by ID."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM user_requests WHERE id = %s", (request_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def update_request_status(request_id: int, status: str, reviewed_by: str, admin_notes: str = None) -> bool:
    """Update the status of a request."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE user_requests 
            SET status = %s, reviewed_at = NOW(), reviewed_by = %s, admin_notes = %s
            WHERE id = %s
        """, (status, reviewed_by, admin_notes, request_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def check_existing_request(email: str) -> Optional[Dict]:
    """Check if there's already a pending request for this email."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM user_requests 
            WHERE email = %s AND status = 'pending'
        """, (email,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


# =============================================================================
# Heroku Integration
# =============================================================================

def add_user_to_heroku(slack_id: str) -> bool:
    """Add a user to Heroku ALLOWED_USERS config var."""
    api_key = os.environ.get("HEROKU_API_KEY")
    app_name = os.environ.get("HEROKU_APP_NAME")
    
    if not api_key or not app_name:
        return False
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/vnd.heroku+json; version=3",
        "Content-Type": "application/json"
    }
    
    try:
        # Get current config vars
        response = requests.get(
            f"https://api.heroku.com/apps/{app_name}/config-vars",
            headers=headers
        )
        if response.status_code != 200:
            return False
        
        config = response.json()
        current_users = config.get("ALLOWED_USERS", "")
        user_set = set(u.strip() for u in current_users.split(",") if u.strip())
        user_set.add(slack_id)
        
        # Update config vars
        response = requests.patch(
            f"https://api.heroku.com/apps/{app_name}/config-vars",
            headers=headers,
            json={"ALLOWED_USERS": ",".join(sorted(user_set))}
        )
        return response.status_code == 200
    except Exception:
        return False


# =============================================================================
# Slack Integration
# =============================================================================

def send_slack_notification(channel: str, message: str) -> bool:
    """Send a notification to a Slack channel."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        return False
    
    try:
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json={"channel": channel, "text": message}
        )
        return response.json().get("ok", False)
    except Exception:
        return False


def lookup_slack_user_by_email(email: str) -> Optional[Dict]:
    """Look up a Slack user by email."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        return None
    
    try:
        response = requests.get(
            "https://slack.com/api/users.lookupByEmail",
            headers={"Authorization": f"Bearer {token}"},
            params={"email": email}
        )
        data = response.json()
        if data.get("ok"):
            return data.get("user")
    except Exception:
        pass
    return None


def invite_user_to_channel(user_id: str, channel_id: str) -> tuple[bool, str]:
    """Invite a user to a Slack channel. Returns (success, message)."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        return False, "SLACK_BOT_TOKEN not configured"
    
    try:
        # First, verify the channel exists and bot can access it
        info_response = requests.get(
            "https://slack.com/api/conversations.info",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            params={"channel": channel_id}
        )
        info_data = info_response.json()
        
        if not info_data.get("ok"):
            error = info_data.get("error", "Unknown error")
            if error == "channel_not_found":
                return False, f"Channel not found or bot is not a member. Please ensure the bot is added to channel {channel_id} and has 'channels:read' scope."
            return False, f"Cannot access channel: {error}"
        
        channel_info = info_data.get("channel", {})
        if not channel_info.get("is_member"):
            return False, f"Bot is not a member of channel {channel_info.get('name', channel_id)}. Please add the bot to the channel first."
        
        # Now attempt the invite
        response = requests.post(
            "https://slack.com/api/conversations.invite",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json={
                "channel": channel_id,
                "users": user_id
            }
        )
        data = response.json()
        if data.get("ok"):
            return True, "Successfully invited to channel"
        else:
            error = data.get("error", "Unknown error")
            if error == "already_in_channel":
                return True, "User is already in the channel"
            elif error == "channel_not_found":
                return False, f"Channel not found. Verify channel ID {channel_id} is correct."
            elif error == "missing_scope":
                return False, "Bot token missing required scope (channels:write or channels:manage). Please add scope and reinstall app."
            return False, f"Slack API error: {error}"
    except Exception as e:
        return False, f"Exception: {str(e)}"


# =============================================================================
# Auth Decorator
# =============================================================================

def admin_required(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# HTML Templates
# =============================================================================

BASE_STYLE = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
    
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    :root {
        --bg-primary: #0a0f1a;
        --bg-secondary: #111827;
        --bg-card: #1a2332;
        --accent-primary: #00d4aa;
        --accent-secondary: #0ea5e9;
        --accent-warning: #f59e0b;
        --accent-danger: #ef4444;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --border-color: #2d3748;
    }
    
    body {
        font-family: 'Space Grotesk', sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        min-height: 100vh;
        line-height: 1.6;
    }
    
    .container {
        max-width: 800px;
        margin: 0 auto;
        padding: 2rem;
    }
    
    .header {
        text-align: center;
        margin-bottom: 3rem;
        padding: 2rem 0;
        border-bottom: 1px solid var(--border-color);
    }
    
    .header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
    }
    
    .header p {
        color: var(--text-secondary);
        font-size: 1.1rem;
    }
    
    .card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 2rem;
        margin-bottom: 1.5rem;
    }
    
    .form-group {
        margin-bottom: 1.5rem;
    }
    
    .form-group label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
        color: var(--text-primary);
    }
    
    .form-group .hint {
        font-size: 0.85rem;
        color: var(--text-secondary);
        margin-top: 0.25rem;
    }
    
    input, textarea, select {
        width: 100%;
        padding: 0.875rem 1rem;
        font-size: 1rem;
        font-family: inherit;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        color: var(--text-primary);
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    
    input:focus, textarea:focus, select:focus {
        outline: none;
        border-color: var(--accent-primary);
        box-shadow: 0 0 0 3px rgba(0, 212, 170, 0.1);
    }
    
    textarea {
        min-height: 120px;
        resize: vertical;
    }
    
    .btn {
        display: inline-block;
        padding: 0.875rem 2rem;
        font-size: 1rem;
        font-weight: 600;
        font-family: inherit;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s;
        text-decoration: none;
        text-align: center;
    }
    
    .btn:hover {
        transform: translateY(-2px);
    }
    
    .btn-primary {
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
        color: var(--bg-primary);
    }
    
    .btn-success {
        background: var(--accent-primary);
        color: var(--bg-primary);
    }
    
    .btn-danger {
        background: var(--accent-danger);
        color: white;
    }
    
    .btn-secondary {
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
    }
    
    .btn-sm {
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
    }
    
    .alert {
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
        font-weight: 500;
    }
    
    .alert-success {
        background: rgba(0, 212, 170, 0.1);
        border: 1px solid var(--accent-primary);
        color: var(--accent-primary);
    }
    
    .alert-error {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid var(--accent-danger);
        color: var(--accent-danger);
    }
    
    .alert-warning {
        background: rgba(245, 158, 11, 0.1);
        border: 1px solid var(--accent-warning);
        color: var(--accent-warning);
    }
    
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        font-size: 0.75rem;
        font-weight: 600;
        border-radius: 9999px;
        text-transform: uppercase;
    }
    
    .badge-pending {
        background: rgba(245, 158, 11, 0.2);
        color: var(--accent-warning);
    }
    
    .badge-approved {
        background: rgba(0, 212, 170, 0.2);
        color: var(--accent-primary);
    }
    
    .badge-denied {
        background: rgba(239, 68, 68, 0.2);
        color: var(--accent-danger);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
    }
    
    th, td {
        padding: 1rem;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }
    
    th {
        font-weight: 600;
        color: var(--text-secondary);
        font-size: 0.875rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    tr:hover {
        background: rgba(255, 255, 255, 0.02);
    }
    
    .actions {
        display: flex;
        gap: 0.5rem;
    }
    
    .nav {
        display: flex;
        gap: 1rem;
        margin-bottom: 2rem;
    }
    
    .nav a {
        color: var(--text-secondary);
        text-decoration: none;
        padding: 0.5rem 1rem;
        border-radius: 6px;
        transition: all 0.2s;
    }
    
    .nav a:hover, .nav a.active {
        background: var(--bg-card);
        color: var(--accent-primary);
    }
    
    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }
    
    .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
    }
    
    .stat-card .number {
        font-size: 2rem;
        font-weight: 700;
        color: var(--accent-primary);
    }
    
    .stat-card .label {
        color: var(--text-secondary);
        font-size: 0.875rem;
        margin-top: 0.25rem;
    }
    
    .slack-id-help {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 1rem;
        margin-top: 1rem;
        font-size: 0.9rem;
    }
    
    .slack-id-help h4 {
        color: var(--accent-secondary);
        margin-bottom: 0.5rem;
    }
    
    .slack-id-help ol {
        margin-left: 1.25rem;
        color: var(--text-secondary);
    }
    
    .slack-id-help li {
        margin-bottom: 0.25rem;
    }
</style>
"""

REGISTRATION_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bio-ISAC Access Request</title>
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Bio-ISAC</h1>
            <p>Vulnerability Intelligence Platform Access Request</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <h2 style="margin-bottom: 1.5rem;">Request Access</h2>
            <form method="POST" action="{{ url_for('register') }}">
                <div class="form-group">
                    <label for="full_name">Full Name *</label>
                    <input type="text" id="full_name" name="full_name" required 
                           placeholder="Enter your full name">
                </div>
                
                <div class="form-group">
                    <label for="email">Email Address *</label>
                    <input type="email" id="email" name="email" required 
                           placeholder="your.email@organization.com">
                    <p class="hint">Use the same email associated with your Slack account</p>
                </div>
                
                <div class="form-group">
                    <label for="organization">Organization</label>
                    <input type="text" id="organization" name="organization" 
                           placeholder="Your company or organization">
                </div>
                
                <div class="form-group">
                    <label for="slack_id">Slack User ID</label>
                    <input type="text" id="slack_id" name="slack_id" 
                           placeholder="e.g., U01234ABCDE" pattern="U[A-Z0-9]+">
                    <div class="slack-id-help">
                        <h4>How to find your Slack ID:</h4>
                        <ol>
                            <li>Open Slack and click on your profile picture</li>
                            <li>Click "Profile" to view your profile</li>
                            <li>Click the "..." menu and select "Copy member ID"</li>
                            <li>Your ID starts with "U" followed by letters/numbers</li>
                        </ol>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="reason">Reason for Access</label>
                    <textarea id="reason" name="reason" 
                              placeholder="Briefly describe why you need access to the Bio-ISAC vulnerability intelligence platform..."></textarea>
                </div>
                
                <button type="submit" class="btn btn-primary" style="width: 100%;">
                    Submit Access Request
                </button>
            </form>
        </div>
        
        <p style="text-align: center; color: var(--text-secondary); font-size: 0.9rem;">
            Your request will be reviewed by a Bio-ISAC administrator.<br>
            You'll be notified once your access has been approved.
        </p>
    </div>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Submitted - Bio-ISAC</title>
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Bio-ISAC</h1>
            <p>Vulnerability Intelligence Platform</p>
        </div>
        
        <div class="card" style="text-align: center;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">✅</div>
            <h2 style="margin-bottom: 1rem;">Request Submitted Successfully!</h2>
            <p style="color: var(--text-secondary); margin-bottom: 2rem;">
                Thank you for your interest in Bio-ISAC. Your access request has been received 
                and is pending administrator review.
            </p>
            <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 8px; text-align: left;">
                <p><strong>What happens next?</strong></p>
                <ol style="margin-left: 1.25rem; margin-top: 0.5rem; color: var(--text-secondary);">
                    <li>An administrator will review your request</li>
                    <li>If approved, you'll be invited to the Bio-ISAC Slack channel</li>
                    <li>You'll then have access to the /bioisac commands</li>
                </ol>
            </div>
            <a href="{{ url_for('register') }}" class="btn btn-secondary" style="margin-top: 2rem;">
                Submit Another Request
            </a>
        </div>
    </div>
</body>
</html>
"""

ADMIN_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Bio-ISAC</title>
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container" style="max-width: 400px;">
        <div class="header">
            <h1>🔐 Admin Login</h1>
            <p>Bio-ISAC Access Management</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <form method="POST">
                <div class="form-group">
                    <label for="password">Admin Password</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="Enter admin password">
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">
                    Login
                </button>
            </form>
        </div>
        
        <p style="text-align: center;">
            <a href="{{ url_for('register') }}" style="color: var(--accent-secondary);">
                ← Back to Registration
            </a>
        </p>
    </div>
</body>
</html>
"""

ADMIN_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Bio-ISAC</title>
    """ + BASE_STYLE + """
</head>
<body>
    <div class="container" style="max-width: 1200px;">
        <div class="header">
            <h1>🛡️ Bio-ISAC Admin</h1>
            <p>Access Request Management</p>
        </div>
        
        <nav class="nav">
            <a href="{{ url_for('admin_dashboard') }}" class="{{ 'active' if show_all is not defined or not show_all else '' }}">
                Pending Requests
            </a>
            <a href="{{ url_for('admin_dashboard', show_all=1) }}" class="{{ 'active' if show_all else '' }}">
                All Requests
            </a>
            <a href="{{ url_for('admin_logout') }}" style="margin-left: auto;">
                Logout
            </a>
        </nav>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{{ pending_count }}</div>
                <div class="label">Pending</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ approved_count }}</div>
                <div class="label">Approved</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ denied_count }}</div>
                <div class="label">Denied</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ total_count }}</div>
                <div class="label">Total</div>
            </div>
        </div>
        
        <div class="card">
            {% if requests %}
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Organization</th>
                            <th>Slack ID</th>
                            <th>Status</th>
                            <th>Requested</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for req in requests %}
                        <tr>
                            <td>{{ req.full_name }}</td>
                            <td>{{ req.email }}</td>
                            <td>{{ req.organization or '-' }}</td>
                            <td>{{ req.slack_id or '-' }}</td>
                            <td>
                                <span class="badge badge-{{ req.status }}">{{ req.status }}</span>
                            </td>
                            <td>{{ req.requested_at.strftime('%Y-%m-%d %H:%M') if req.requested_at else '-' }}</td>
                            <td class="actions">
                                {% if req.status == 'pending' %}
                                    <form method="POST" action="{{ url_for('admin_approve', request_id=req.id) }}" style="display: inline;">
                                        <button type="submit" class="btn btn-success btn-sm">Approve</button>
                                    </form>
                                    <form method="POST" action="{{ url_for('admin_deny', request_id=req.id) }}" style="display: inline;">
                                        <button type="submit" class="btn btn-danger btn-sm">Deny</button>
                                    </form>
                                {% else %}
                                    <span style="color: var(--text-secondary); font-size: 0.875rem;">
                                        {{ req.reviewed_by or 'System' }} @ {{ req.reviewed_at.strftime('%m/%d') if req.reviewed_at else '-' }}
                                    </span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p style="text-align: center; color: var(--text-secondary); padding: 3rem;">
                    No {{ 'pending ' if not show_all else '' }}requests found.
                </p>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""


# =============================================================================
# Routes
# =============================================================================

@app.route("/", methods=["GET"])
def index():
    """Redirect to registration form."""
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Public registration form."""
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        organization = request.form.get("organization", "").strip()
        slack_id = request.form.get("slack_id", "").strip().upper()
        reason = request.form.get("reason", "").strip()
        
        # Validation
        if not full_name or not email:
            flash("Name and email are required.", "error")
            return render_template_string(REGISTRATION_TEMPLATE)
        
        # Check for existing pending request
        existing = check_existing_request(email)
        if existing:
            flash("You already have a pending request. Please wait for administrator review.", "warning")
            return render_template_string(REGISTRATION_TEMPLATE)
        
        # If no Slack ID provided, try to look it up
        if not slack_id:
            user = lookup_slack_user_by_email(email)
            if user:
                slack_id = user.get("id", "")
        
        try:
            request_id = create_request(full_name, email, organization, slack_id, reason)
            
            # Notify admin channel if configured
            admin_channel = os.environ.get("ADMIN_NOTIFICATION_CHANNEL")
            if admin_channel:
                send_slack_notification(
                    admin_channel,
                    f"📋 *New Access Request*\n"
                    f"• Name: {full_name}\n"
                    f"• Email: {email}\n"
                    f"• Organization: {organization or 'N/A'}\n"
                    f"• Slack ID: {slack_id or 'Not provided'}\n"
                    f"• Reason: {reason or 'Not provided'}\n\n"
                    f"_Review at: {request.host_url}admin_"
                )
            
            return render_template_string(SUCCESS_TEMPLATE)
        except Exception as e:
            flash(f"Error submitting request. Please try again.", "error")
            return render_template_string(REGISTRATION_TEMPLATE)
    
    return render_template_string(REGISTRATION_TEMPLATE)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Admin login page."""
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["admin_authenticated"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid password.", "error")
    
    return render_template_string(ADMIN_LOGIN_TEMPLATE)


@app.route("/admin/logout")
def admin_logout():
    """Admin logout."""
    session.pop("admin_authenticated", None)
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET"])
@admin_required
def admin_dashboard():
    """Admin dashboard showing access requests."""
    show_all = request.args.get("show_all", False)
    
    if show_all:
        requests_list = get_all_requests()
    else:
        requests_list = get_pending_requests()
    
    # Get counts for stats
    all_requests = get_all_requests()
    pending_count = sum(1 for r in all_requests if r["status"] == "pending")
    approved_count = sum(1 for r in all_requests if r["status"] == "approved")
    denied_count = sum(1 for r in all_requests if r["status"] == "denied")
    
    return render_template_string(
        ADMIN_DASHBOARD_TEMPLATE,
        requests=requests_list,
        show_all=show_all,
        pending_count=pending_count,
        approved_count=approved_count,
        denied_count=denied_count,
        total_count=len(all_requests)
    )


@app.route("/admin/approve/<int:request_id>", methods=["POST"])
@admin_required
def admin_approve(request_id):
    """Approve an access request."""
    try:
        req = get_request_by_id(request_id)
        if not req:
            flash("Request not found.", "error")
            return redirect(url_for("admin_dashboard"))
        
        if req["status"] != "pending":
            flash("Request has already been processed.", "warning")
            return redirect(url_for("admin_dashboard"))
        
        # Try to look up Slack ID if not provided
        slack_id = req.get("slack_id")
        if not slack_id:
            try:
                user = lookup_slack_user_by_email(req["email"])
                if user:
                    slack_id = user.get("id")
            except Exception as e:
                # If lookup fails, continue without Slack ID
                pass
        
        if not slack_id:
            flash(f"Cannot approve: No Slack ID found for {req['email']}. Please add their Slack ID manually.", "error")
            return redirect(url_for("admin_dashboard"))
        
        # Add to Heroku
        heroku_success = add_user_to_heroku(slack_id)
        
        # Invite to Bio-ISAC channel if configured
        channel_invited = False
        channel_message = ""
        bioisac_channel = os.environ.get("BIOISAC_CHANNEL") or os.environ.get("DIGEST_CHANNEL")
        if bioisac_channel:
            try:
                channel_invited, channel_message = invite_user_to_channel(slack_id, bioisac_channel)
            except Exception as e:
                # If invitation fails, continue anyway
                channel_message = f"Exception: {str(e)}"
        
        # Update request status
        try:
            update_request_status(request_id, "approved", "admin")
        except Exception as e:
            flash(f"Error updating request status: {str(e)}", "error")
            return redirect(url_for("admin_dashboard"))
        
        # Build success message
        if heroku_success and channel_invited:
            flash(f"✅ Approved {req['full_name']} and added {slack_id} to Heroku ALLOWED_USERS. User has been invited to the Bio-ISAC channel.", "success")
        elif heroku_success:
            error_detail = channel_message if channel_message else "channel may not be configured"
            flash(f"✅ Approved {req['full_name']} and added {slack_id} to Heroku ALLOWED_USERS. Note: Could not invite to channel ({error_detail}).", "warning")
        else:
            flash(f"✅ Approved {req['full_name']}. Note: Could not auto-update Heroku. Please add {slack_id} manually.", "warning")
        
        return redirect(url_for("admin_dashboard"))
    except Exception as e:
        flash(f"Error approving request: {str(e)}", "error")
        return redirect(url_for("admin_dashboard"))


@app.route("/admin/deny/<int:request_id>", methods=["POST"])
@admin_required
def admin_deny(request_id):
    """Deny an access request."""
    try:
        req = get_request_by_id(request_id)
        if not req:
            flash("Request not found.", "error")
            return redirect(url_for("admin_dashboard"))
        
        update_request_status(request_id, "denied", "admin")
        flash(f"Request from {req['full_name']} has been denied.", "success")
        
        return redirect(url_for("admin_dashboard"))
    except Exception as e:
        flash(f"Error denying request: {str(e)}", "error")
        return redirect(url_for("admin_dashboard"))


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "bio-isac-registration"})


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)

