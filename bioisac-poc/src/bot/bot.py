"""Slack Bolt app for Bio-ISAC vulnerability triage."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional

import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from ..etl import queries


def load_env() -> None:
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


def parse_allow_list(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def get_admin_users() -> List[str]:
    """Get list of admin user IDs from environment."""
    return parse_allow_list(os.environ.get("ADMIN_USERS", ""))


def is_admin(user_id: str) -> bool:
    """Check if a user is an admin."""
    admin_users = get_admin_users()
    # If no admins configured, allow all allowed users to be admins
    if not admin_users:
        return True
    return user_id in admin_users


# =============================================================================
# Heroku Config Management (for auto-sync and admin commands)
# =============================================================================

def get_heroku_allowed_users() -> set:
    """Get current ALLOWED_USERS from Heroku config."""
    api_key = os.environ.get("HEROKU_API_KEY")
    app_name = os.environ.get("HEROKU_APP_NAME")
    
    if not api_key or not app_name:
        return set()
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/vnd.heroku+json; version=3",
    }
    
    try:
        response = requests.get(
            f"https://api.heroku.com/apps/{app_name}/config-vars",
            headers=headers
        )
        if response.status_code == 200:
            config = response.json()
            allowed = config.get("ALLOWED_USERS", "")
            return set(u.strip() for u in allowed.split(",") if u.strip())
    except Exception:
        pass
    return set()


def update_heroku_allowed_users(user_ids: set) -> bool:
    """Update ALLOWED_USERS on Heroku."""
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
        response = requests.patch(
            f"https://api.heroku.com/apps/{app_name}/config-vars",
            headers=headers,
            json={"ALLOWED_USERS": ",".join(sorted(user_ids))}
        )
        return response.status_code == 200
    except Exception:
        return False


def add_user_to_allowed(user_id: str) -> tuple[bool, str]:
    """Add a user to ALLOWED_USERS. Returns (success, message)."""
    current = get_heroku_allowed_users()
    if user_id in current:
        return True, f"User `{user_id}` is already in ALLOWED_USERS"
    
    current.add(user_id)
    if update_heroku_allowed_users(current):
        return True, f"Successfully added `{user_id}` to ALLOWED_USERS"
    return False, f"Failed to add `{user_id}` - check HEROKU_API_KEY and HEROKU_APP_NAME"


def remove_user_from_allowed(user_id: str) -> tuple[bool, str]:
    """Remove a user from ALLOWED_USERS. Returns (success, message)."""
    current = get_heroku_allowed_users()
    if user_id not in current:
        return True, f"User `{user_id}` is not in ALLOWED_USERS"
    
    current.discard(user_id)
    if update_heroku_allowed_users(current):
        return True, f"Successfully removed `{user_id}` from ALLOWED_USERS"
    return False, f"Failed to remove `{user_id}` - check HEROKU_API_KEY and HEROKU_APP_NAME"


def get_slack_user_info(client, user_id: str) -> dict:
    """Get Slack user info."""
    try:
        result = client.users_info(user=user_id)
        if result.get("ok"):
            return result.get("user", {})
    except Exception:
        pass
    return {}


def ensure_authorized(user_id: str, channel_id: str) -> None:
    allowed_users = parse_allow_list(os.environ.get("ALLOWED_USERS", ""))
    allowed_channels = parse_allow_list(os.environ.get("ALLOWED_CHANNELS", ""))
    if allowed_users and user_id not in allowed_users:
        raise PermissionError("User not authorized")
    if allowed_channels and channel_id not in allowed_channels:
        raise PermissionError("Channel not authorized")


def _format_vendor_device(row: dict) -> str:
    vendor = row.get("vendor")
    product = row.get("product")
    if vendor and product:
        return f"{vendor}/{product}"
    if vendor:
        return vendor
    if product:
        return product
    return "Unspecified device"


def _get_severity_badge(row: dict) -> str:
    """Return a clean severity badge with color coding based on CVSS score."""
    cvss = row.get("cvss_base")
    if cvss:
        if cvss >= 9.0:
            return "🔴 CRITICAL"  # Red for critical
        elif cvss >= 7.0:
            return "🟠 HIGH"  # Orange for high
        elif cvss >= 4.0:
            return "🟡 MEDIUM"  # Yellow for medium
        else:
            return "🟢 LOW"  # Green for low
    severity = row.get("severity") or ""
    if severity:
        severity = severity.upper()
        if severity == "CRITICAL":
            return "🔴 CRITICAL"
        elif severity == "HIGH":
            return "🟠 HIGH"
        elif severity == "MEDIUM":
            return "🟡 MEDIUM"
        elif severity == "LOW":
            return "🟢 LOW"
    return "⚪ UNRATED"  # White/gray for unrated


def _get_priority_indicators(row: dict) -> str:
    """Return clean priority indicators based on flags."""
    indicators = []
    if row.get("kev_flag"):
        indicators.append("KEV")
    if row.get("medical_flag"):
        indicators.append("MEDICAL")
    if row.get("ics_flag"):
        indicators.append("ICS")
    if row.get("bio_keyword_flag"):
        indicators.append("BIO-RELEVANT")
    return " • ".join(indicators) if indicators else ""


def format_vuln(row: dict, position: Optional[int] = None) -> str:
    severity_badge = _get_severity_badge(row)
    priority_indicators = _get_priority_indicators(row)
    
    # Build CVSS label
    cvss_label = f"CVSS {row['cvss_base']:.1f}" if row.get("cvss_base") else "No CVSS Score"
    
    # Header with position number
    prefix = f"*{position}.*  " if position is not None else ""
    cve_id = row.get("cve_id") or "Unknown CVE"
    header = f"{prefix}*{cve_id}*  {severity_badge}"
    
    # Add priority indicators if any
    if priority_indicators:
        header += f"\n`{priority_indicators}`"
    
    # Subheader with device and CVSS
    subheader = f"{cvss_label}  •  {_format_vendor_device(row)}"
    
    # Summary
    summary = row.get("plain_summary") or (row.get("description") or "")[:200]
    if summary and not summary.endswith("."):
        summary = summary.rstrip(".") + "."
    
    # Build the vulnerability card
    lines = [header, subheader, ""]
    
    if summary:
        lines.append(summary)
        lines.append("")
    
    # Recommended action
    safe_action = row.get("safe_action") or "Review details and assess patch priority."
    lines.append(f"*Recommended Action:*\n{safe_action}")
    
    # Advisory links - always show NVD, optionally show vendor advisory
    advisory = row.get("advisory_url")
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id and cve_id != "Unknown CVE" else None
    
    # Filter out problematic URLs (error pages, 404s, etc.)
    def is_valid_advisory_url(url: str) -> bool:
        """Check if advisory URL looks valid (not an error page)."""
        if not url:
            return False
        url_lower = url.lower()
        problematic_patterns = ["/error/", "/Error/", "/404", "/404.html"]
        return not any(pattern in url_lower for pattern in problematic_patterns)
    
    advisory_links = []
    if advisory and advisory != nvd_url and is_valid_advisory_url(advisory):
        # Show vendor advisory if it exists, is different from NVD, and looks valid
        advisory_links.append(f"<{advisory}|Vendor Advisory>")
    if nvd_url:
        # Always show NVD link as reliable source
        advisory_links.append(f"<{nvd_url}|NVD Details>")
    
    if advisory_links:
        lines.append(f"\n*Advisory:* {' • '.join(advisory_links)}")
    
    # Metadata footer
    metadata = []
    source_list = row.get("source_list") or []
    if not isinstance(source_list, list):
        source_list = []
    sources = ", ".join(source_list) if source_list else ""
    if sources:
        metadata.append(f"Sources: {sources}")
    
    bio_score = row.get("bio_score")
    if bio_score is not None:
        metadata.append(f"Bio-Relevance: {bio_score}/10")
    
    if metadata:
        lines.append("")
        lines.append(f"_{' • '.join(metadata)}_")
    
    return "\n".join(lines)


def render_message(rows: Iterable[dict], hint: bool = False) -> str:
    entries = [format_vuln(row, idx + 1) for idx, row in enumerate(rows)]
    body = "\n\n────────────────────────────────\n\n".join(entries)
    if hint:
        body = f"{body}\n\n────────────────────────────────\n\n_Type `/bioisac help` for available commands_"
    return body


def format_no_results_message(context_type: str, context_value: str = "", suggestion: str = "") -> str:
    """
    Standardized helper for 'no results' responses across all commands.
    
    Args:
        context_type: Type of query (e.g., "Timeframe Query", "Search Query", "Database Query")
        context_value: The specific value searched (e.g., "Last 24 hours", "illumina", "CVE-2024-1234")
        suggestion: Optional next step suggestion for the user
    
    Returns:
        Formatted professional "no results" message
    """
    message = f"*{context_type}:* {context_value}\n*Results:* No matching vulnerabilities found"
    if suggestion:
        message += f"\n\n_{suggestion}_"
    return message


def format_access_denied_message() -> str:
    """
    Standardized helper for permission/authorization errors.
    
    Returns:
        Formatted professional access denied message
    """
    return """*Access Denied:* Authorization required

To request access to the Bio-ISAC vulnerability intelligence platform:

1. Contact your Bio-ISAC administrator
2. Provide your Slack user ID (found in your Slack profile URL or by asking the admin)
3. The administrator will add your user ID to the allowed users list

_Note: On Heroku, the bot restarts automatically when config vars change. For local development, restart the bot manually._"""


# Maximum number of vulnerabilities to display in list responses
# Adjust this value to change pagination behavior across all list commands
MAX_DISPLAY_RESULTS = 10


def apply_pagination(rows: List[dict], command_context: str = "") -> tuple[List[dict], str]:
    """
    Apply pagination/truncation to result lists to prevent overwhelming Slack messages.
    
    Args:
        rows: List of vulnerability records from database
        command_context: Optional context string for the truncation message (e.g., "search term" or "timeframe")
    
    Returns:
        Tuple of (truncated_rows, footer_message)
        - truncated_rows: List limited to MAX_DISPLAY_RESULTS
        - footer_message: Empty string if no truncation, otherwise a message explaining truncation
    """
    total_count = len(rows)
    if total_count <= MAX_DISPLAY_RESULTS:
        return rows, ""
    
    # Truncate to max display results
    truncated = rows[:MAX_DISPLAY_RESULTS]
    
    # Build truncation message
    footer = f"\n\n────────────────────────────────\n\n"
    footer += f"*Results Truncated:* Showing {MAX_DISPLAY_RESULTS} of {total_count} total matches\n\n"
    
    if command_context:
        footer += f"_{command_context}_"
    else:
        footer += "_Refine your query to see more specific results, or adjust search parameters_"
    
    return truncated, footer


def main() -> None:
    load_env()
    app = App(token=os.environ["SLACK_BOT_TOKEN"])

    @app.error
    def handle_errors(error, body, logger):
        logger.warning("Slack handler error: %s body=%s", error, body)

    # =========================================================================
    # Automated Channel Join Detection
    # =========================================================================
    
    @app.event("member_joined_channel")
    def handle_member_joined(event, client, logger):
        """Auto-add users to ALLOWED_USERS when they join the Bio-ISAC channel."""
        channel_id = event.get("channel")
        user_id = event.get("user")
        
        # Only process for the configured Bio-ISAC channel
        bioisac_channel = os.environ.get("BIOISAC_CHANNEL") or os.environ.get("DIGEST_CHANNEL")
        auto_add_enabled = os.environ.get("AUTO_ADD_CHANNEL_MEMBERS", "false").lower() == "true"
        
        if not bioisac_channel or channel_id != bioisac_channel:
            return
        
        if not auto_add_enabled:
            logger.info(f"User {user_id} joined channel but AUTO_ADD_CHANNEL_MEMBERS is disabled")
            return
        
        # Check if user is a bot
        user_info = get_slack_user_info(client, user_id)
        if user_info.get("is_bot"):
            logger.info(f"Skipping bot user {user_id}")
            return
        
        # Add user to ALLOWED_USERS
        success, message = add_user_to_allowed(user_id)
        
        if success:
            logger.info(f"Auto-added user {user_id} to ALLOWED_USERS: {message}")
            
            # Notify admin channel if configured
            admin_channel = os.environ.get("ADMIN_NOTIFICATION_CHANNEL")
            if admin_channel:
                user_name = user_info.get("real_name") or user_info.get("name", user_id)
                try:
                    client.chat_postMessage(
                        channel=admin_channel,
                        text=f"🆕 *Auto-Added New User*\n"
                             f"• User: {user_name} (`{user_id}`)\n"
                             f"• Channel: <#{channel_id}>\n"
                             f"• Status: {message}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to send admin notification: {e}")
        else:
            logger.error(f"Failed to auto-add user {user_id}: {message}")

    @app.command("/bioisac")
    def handle_bioisac(ack, respond, body, logger):
        ack()
        text = body.get("text", "").strip()
        user_id = body.get("user_id")
        channel_id = body.get("channel_id")
        try:
            ensure_authorized(user_id, channel_id)
        except PermissionError:
            respond(format_access_denied_message())
            return
        
        # Help command
        if not text or text == "help":
            # Fetch real examples from database
            example_cve = "CVE-2024-1234"  # fallback
            example_keyword = "vulnerability"  # fallback
            try:
                conn = queries.get_connection()
                try:
                    examples = queries.get_example_data(conn)
                    example_cve = examples["cve_id"] or example_cve
                    example_keyword = examples["search_keyword"] or example_keyword
                except Exception as e:
                    logger.warning("Failed to fetch example data for help: %s", e)
                finally:
                    conn.close()
            except Exception as e:
                logger.warning("Failed to connect to database for help examples: %s", e)
            
            help_text = f"""*Bio-ISAC Vulnerability Intelligence Platform*

*AVAILABLE COMMANDS*

*`/bioisac help`*
Display this help documentation

────────────────────────────────

*`/bioisac top [n]`*
Retrieve top N vulnerabilities ranked by bio-relevance score
• Default: 10 vulnerabilities (can request up to 100)
• Example: `/bioisac top 20` to view top 20 vulnerabilities

────────────────────────────────

*`/bioisac search <keyword>`*
Search vulnerability database by CVE ID, vendor, product, or title
• Example: `/bioisac search {example_keyword}`

────────────────────────────────

*`/bioisac recent [hours]`*
Display vulnerabilities discovered within specified timeframe
• Default: 24 hours

────────────────────────────────

*`/bioisac stats`*
View comprehensive vulnerability statistics and metrics

────────────────────────────────

*`/bioisac detail <CVE-ID>`*
Retrieve detailed information for a specific CVE identifier
• Example: `/bioisac detail {example_cve}`

────────────────────────────────

*`/bioisac digest-setup`*
Customize your daily digest preferences
• `/bioisac digest-setup show` - View your current preferences
• `/bioisac digest-setup set <filters>` - Configure filters (medical, ics, bio, kev, cvss-min, bio-min, limit)
• `/bioisac digest-setup disable` - Disable custom digest
• Example: `/bioisac digest-setup set medical cvss-min:7.0`

────────────────────────────────

*PRIORITY INDICATORS*

`KEV` - CISA Known Exploited Vulnerability
`MEDICAL` - Medical device related
`ICS` - Industrial Control System
`BIO-RELEVANT` - Bio-industry keyword match

*SEVERITY CLASSIFICATION*

🔴 CRITICAL - CVSS 9.0-10.0
🟠 HIGH - CVSS 7.0-8.9
🟡 MEDIUM - CVSS 4.0-6.9
🟢 LOW - CVSS 0.1-3.9

────────────────────────────────

*DAILY DIGEST*
Automated daily vulnerability summaries are posted to configured channels.
Use `/bioisac digest-setup` to customize what appears in your personal digest.

────────────────────────────────

*ADMIN COMMANDS* (Administrators only)

`/bioisac admin` - View admin command help
`/bioisac admin add-user <id>` - Add user to allowed list
`/bioisac admin remove-user <id>` - Remove user from allowed list
`/bioisac admin list-users` - List all authorized users
`/bioisac admin sync-channel` - Sync channel members to allowed list

────────────────────────────────

_For technical support, contact your Bio-ISAC security administrator_"""
            respond(help_text)
            return
        
        # Top command
        if text.startswith("top"):
            parts = text.split()
            limit = 10  # Default changed from 5 to 10
            if len(parts) >= 2:
                if not parts[1].isdigit():
                    respond("*Usage:* `/bioisac top [n]`\n\n*Valid Range:* 1-100 vulnerabilities\n\n_Example:_ `/bioisac top 20` to view top 20 vulnerabilities")
                    return
                limit = int(parts[1])
                if limit < 1 or limit > 100:
                    respond(f"*Invalid Parameter:* Number `{limit}` is out of range\n\n*Valid Range:* 1-100 vulnerabilities\n\n_Example:_ `/bioisac top 20`")
                    return
            try:
                conn = queries.get_connection()
            except Exception as e:
                respond(f"*Database Error:* Failed to connect to database\n\n_Contact your administrator if this persists_")
                logger.error("Database connection error in top command: %s", e)
                return
            try:
                rows = queries.get_top_vulns(conn, limit=limit)
            except Exception as e:
                conn.close()
                respond(f"*Database Error:* Failed to query vulnerability data\n\n_Contact your administrator if this persists_")
                logger.error("Database query error in top command: %s", e)
                return
            conn.close()
            if not rows:
                respond(format_no_results_message(
                    "Database Query",
                    "Top vulnerabilities",
                    "Database may be empty. Run ETL process to populate vulnerability data."
                ))
                return
            
            # For top command, show all requested results (no pagination truncation)
            # But warn if they requested more than recommended
            header = f"*Top {len(rows)} Vulnerabilities — Ranked by Bio-Relevance*\n\n"
            footer = ""
            if limit > 20:
                footer = "\n\n────────────────────────────────\n\n_Note: Large result sets may be truncated by Slack. Consider using `/bioisac search <keyword>` for more focused queries._"
            
            respond(header + render_message(rows, hint=True) + footer)
            return
        
        # Search command
        if text.startswith("search"):
            term = text.partition(" ")[2].strip()
            if not term:
                respond("*Usage:* `/bioisac search <keyword>`\n\n_Example:_ `/bioisac search illumina`")
                return
            try:
                conn = queries.get_connection()
            except Exception as e:
                respond(f"*Database Error:* Failed to connect to database\n\n_Contact your administrator if this persists_")
                logger.error("Database connection error in search command: %s", e)
                return
            try:
                rows = queries.search_vulns(conn, term)
            except Exception as e:
                conn.close()
                respond(f"*Database Error:* Failed to query vulnerability data\n\n_Contact your administrator if this persists_")
                logger.error("Database query error in search command: %s", e)
                return
            conn.close()
            if not rows:
                respond(format_no_results_message(
                    "Search Query",
                    f"`{term}`",
                    "Verify keyword spelling and try alternative terms, or use `/bioisac top` to view all vulnerabilities"
                ))
                return
            
            # Apply pagination to prevent overwhelming messages
            display_rows, truncation_footer = apply_pagination(
                rows,
                f"Narrow your search with more specific keywords to see additional results"
            )
            
            header = f"*Search Results for* `{term}` *— {len(display_rows)} of {len(rows)} matches*\n\n"
            respond(header + render_message(display_rows, hint=False) + truncation_footer)
            return
        
        # Recent command
        if text.startswith("recent"):
            logger.info("Recent command received: text=%s", text)
            try:
                parts = text.split()
                hours = 24  # Default
                
                # Validate hours parameter if provided
                if len(parts) >= 2:
                    if not parts[1].isdigit():
                        respond("*Usage:* `/bioisac recent [hours]`\n\n*Valid Range:* 1-168 hours (1 hour to 7 days)\n\n_Example:_ `/bioisac recent 48` to view vulnerabilities from the last 48 hours")
                        return
                    hours = int(parts[1])
                    if hours < 1 or hours > 168:
                        respond(f"*Invalid Parameter:* Hours value `{hours}` is out of range\n\n*Valid Range:* 1-168 hours (1 hour to 7 days)\n\n_Example:_ `/bioisac recent 48`")
                        return
                
                try:
                    conn = queries.get_connection()
                except Exception as e:
                    respond(f"*Database Error:* Failed to connect to database\n\n_Contact your administrator if this persists_")
                    logger.error("Database connection error in recent command: %s", e)
                    return
                try:
                    rows = queries.get_recent_vulns(conn, hours=hours, limit=20)
                except Exception as e:
                    conn.close()
                    respond(f"*Database Error:* Failed to query vulnerability data\n\n_Contact your administrator if this persists_")
                    logger.error("Database query error in recent command: %s", e)
                    return
                conn.close()
                if not rows:
                    respond(format_no_results_message(
                        "Timeframe Query",
                        f"Last {hours} hours",
                        "Try expanding the timeframe or use `/bioisac top` to view all vulnerabilities"
                    ))
                    return
                
                # Apply pagination to prevent overwhelming messages
                display_rows, truncation_footer = apply_pagination(
                    rows,
                    f"Narrow the timeframe with `/bioisac recent <hours>` to see more focused results"
                )
                
                header = f"*Recent Vulnerabilities — Last {hours} Hours*\n{len(display_rows)} of {len(rows)} entries shown\n\n"
                respond(header + render_message(display_rows, hint=False) + truncation_footer)
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                respond(f"*Error:* An unexpected error occurred while processing the recent command\n\n*Error Type:* `{error_type}`\n*Details:* `{error_msg}`\n\n_Contact your administrator if this persists_")
                logger.error("Unexpected error in recent command: %s", e, exc_info=True)
            return
        
        # Stats command
        if text == "stats":
            try:
                conn = queries.get_connection()
            except Exception as e:
                respond(f"*Database Error:* Failed to connect to database\n\n_Contact your administrator if this persists_")
                logger.error("Database connection error in stats command: %s", e)
                return
            try:
                cursor = conn.cursor(dictionary=True)
                
                # Total count
                cursor.execute("SELECT COUNT(*) as total FROM vulns")
                total = cursor.fetchone()["total"]
                
                # By severity
                cursor.execute("""
                    SELECT 
                        SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN cvss_base > 0 AND cvss_base < 4.0 THEN 1 ELSE 0 END) as low
                    FROM vulns
                """)
                severity_counts = cursor.fetchone()
                
                # Priority flags
                cursor.execute("""
                    SELECT 
                        SUM(kev_flag) as kev,
                        SUM(medical_flag) as medical,
                        SUM(ics_flag) as ics,
                        SUM(bio_keyword_flag) as bio
                    FROM tags
                """)
                flag_counts = cursor.fetchone()
                
                # Recent (last 24h)
                cursor.execute("SELECT COUNT(*) as recent FROM tags WHERE last_seen >= (NOW() - INTERVAL 24 HOUR)")
                recent_count = cursor.fetchone()["recent"]
                
                cursor.close()
                conn.close()
            except Exception as e:
                try:
                    cursor.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                respond(f"*Database Error:* Failed to query statistics\n\n_Contact your administrator if this persists_")
                logger.error("Database query error in stats command: %s", e)
                return
            
            stats_text = f"""*Bio-ISAC Vulnerability Intelligence — System Statistics*

*DATABASE METRICS*

Total Vulnerabilities: `{total:,}`
Recent Activity (24h): `{recent_count:,}`

────────────────────────────────

*SEVERITY DISTRIBUTION*

▪️ CRITICAL: {severity_counts['critical'] or 0:,}
▪️ HIGH: {severity_counts['high'] or 0:,}
▪️ MEDIUM: {severity_counts['medium'] or 0:,}
▪️ LOW: {severity_counts['low'] or 0:,}

────────────────────────────────

*PRIORITY CLASSIFICATION*

KEV (Known Exploited): {flag_counts['kev'] or 0:,}
Medical Devices: {flag_counts['medical'] or 0:,}
ICS/SCADA Systems: {flag_counts['ics'] or 0:,}
Bio-Industry Relevant: {flag_counts['bio'] or 0:,}

────────────────────────────────

_Statistics generated in real-time from production database_"""
            respond(stats_text)
            return
        
        # Detail command
        if text.startswith("detail"):
            cve_input = text.partition(" ")[2].strip()
            if not cve_input:
                respond("*Usage:* `/bioisac detail <CVE-ID>`\n\n_Example:_ `/bioisac detail CVE-2024-1234`")
                return
            
            # Normalize CVE ID: handle "cve-2024-1234", "CVE-2024-1234", "2024-1234", extra whitespace, etc.
            cve_id = cve_input.upper().strip()
            # Remove "CVE-" or "CVE " prefix if present, then re-add it consistently
            if cve_id.startswith("CVE-") or cve_id.startswith("CVE "):
                cve_id = cve_id[4:].strip()
            # Remove any remaining hyphens or spaces at start
            cve_id = cve_id.lstrip("- ")
            # Reconstruct canonical form
            cve_id = f"CVE-{cve_id}"
            
            # Validate CVE ID format: CVE-YYYY-NNNN (where NNNN is 4+ digits)
            cve_pattern = r"^CVE-\d{4}-\d{4,}$"
            if not re.match(cve_pattern, cve_id):
                respond(f"*Invalid CVE Format:* `{cve_id}`\n\n*Expected Format:* CVE-YYYY-NNNN (e.g., CVE-2024-1234)\n\n_Example:_ `/bioisac detail CVE-2024-1234`")
                return
            
            try:
                conn = queries.get_connection()
            except Exception as e:
                respond(f"*Database Error:* Failed to connect to database\n\n_Contact your administrator if this persists_")
                logger.error("Database connection error in detail command: %s", e)
                return
            try:
                rows = queries.search_vulns(conn, cve_id)
            except Exception as e:
                conn.close()
                respond(f"*Database Error:* Failed to query vulnerability data\n\n_Contact your administrator if this persists_")
                logger.error("Database query error in detail command: %s", e)
                return
            conn.close()
            if not rows:
                respond(format_no_results_message(
                    "CVE Query",
                    f"`{cve_id}`",
                    "Verify the CVE ID and retry, or use `/bioisac search` for broader queries"
                ))
                return
            # Return just the first match without numbering
            header = f"*Vulnerability Detail Report — {cve_id}*\n\n"
            respond(header + format_vuln(rows[0], position=None))
            return
        
        # Digest setup command
        if text.startswith("digest-setup") or text.startswith("digest_setup"):
            parts = text.split()
            if len(parts) < 2:
                help_text = """*Daily Digest Customization*

*Usage:* `/bioisac digest-setup <action> [options]`

*ACTIONS:*

`/bioisac digest-setup show`
View your current digest preferences

`/bioisac digest-setup set <filters>`
Configure your digest filters

*FILTER OPTIONS:*
• `medical` - Only medical device vulnerabilities
• `ics` - Only ICS/SCADA vulnerabilities  
• `bio` - Only bio-keyword relevant vulnerabilities
• `kev` - Only CISA Known Exploited Vulnerabilities
• `cvss-min:<score>` - Minimum CVSS score (e.g., `cvss-min:7.0`)
• `bio-min:<score>` - Minimum bio-relevance score (e.g., `bio-min:5`)
• `limit:<n>` - Number of vulnerabilities to show (default: 10)

*EXAMPLES:*

`/bioisac digest-setup set medical cvss-min:7.0`
→ Only medical device vulnerabilities with CVSS ≥ 7.0

`/bioisac digest-setup set ics kev`
→ Only ICS vulnerabilities that are in CISA KEV

`/bioisac digest-setup set bio bio-min:6 limit:15`
→ Bio-relevant vulnerabilities with score ≥ 6, show 15

`/bioisac digest-setup set cvss-min:9.0`
→ Only critical vulnerabilities (CVSS ≥ 9.0)

`/bioisac digest-setup disable`
→ Disable your personalized digest (revert to default)

*NOTE:* Preferences apply to your personal digest. Channel admins can set channel-wide preferences."""
                respond(help_text)
                return
            
            action = parts[1].lower()
            
            try:
                conn = queries.get_connection()
            except Exception as e:
                respond(f"*Database Error:* Failed to connect\n\n_Contact your administrator_")
                logger.error("Database connection error in digest-setup: %s", e)
                return
            
            try:
                if action == "show":
                    pref = queries.get_digest_preference(conn, user_id=user_id, preference_name="default")
                    if not pref:
                        respond("*Current Preferences:* Default (no custom filters)\n\nUse `/bioisac digest-setup set` to configure filters")
                    else:
                        filters = []
                        # Check boolean flags (MySQL TINYINT(1) returns as 0/1, not bool)
                        if pref.get("medical_flag") == 1:
                            filters.append("Medical devices")
                        if pref.get("ics_flag") == 1:
                            filters.append("ICS/SCADA")
                        if pref.get("bio_keyword_flag") == 1:
                            filters.append("Bio-keywords")
                        if pref.get("kev_flag") == 1:
                            filters.append("CISA KEV")
                        if pref.get("min_cvss"):
                            filters.append(f"CVSS ≥ {pref['min_cvss']}")
                        if pref.get("min_bio_score"):
                            filters.append(f"Bio-score ≥ {pref['min_bio_score']}")
                        
                        status = "Enabled" if pref.get("enabled") else "Disabled"
                        limit = pref.get("limit_count", 10)
                        
                        response = f"""*Your Digest Preferences*

*Status:* {status}
*Limit:* {limit} vulnerabilities
*Filters:* {', '.join(filters) if filters else 'None (all vulnerabilities)'}

Use `/bioisac digest-setup set` to modify"""
                        respond(response)
                
                elif action == "set":
                    # Parse filter options
                    medical_flag = None
                    ics_flag = None
                    bio_keyword_flag = None
                    kev_flag = None
                    min_cvss = None
                    min_bio_score = None
                    limit_count = 10
                    
                    for part in parts[2:]:
                        part_lower = part.lower()
                        if part_lower == "medical":
                            medical_flag = True
                        elif part_lower == "ics":
                            ics_flag = True
                        elif part_lower == "bio":
                            bio_keyword_flag = True
                        elif part_lower == "kev":
                            kev_flag = True
                        elif part_lower.startswith("cvss-min:"):
                            try:
                                min_cvss = float(part_lower.split(":")[1])
                            except (ValueError, IndexError):
                                respond(f"*Invalid CVSS value:* `{part}`\n\nUse format: `cvss-min:7.0`")
                                conn.close()
                                return
                        elif part_lower.startswith("bio-min:"):
                            try:
                                min_bio_score = int(part_lower.split(":")[1])
                            except (ValueError, IndexError):
                                respond(f"*Invalid bio-score value:* `{part}`\n\nUse format: `bio-min:5`")
                                conn.close()
                                return
                        elif part_lower.startswith("limit:"):
                            try:
                                limit_count = int(part_lower.split(":")[1])
                                if limit_count < 1 or limit_count > 50:
                                    respond("*Invalid limit:* Must be between 1 and 50")
                                    conn.close()
                                    return
                            except (ValueError, IndexError):
                                respond(f"*Invalid limit value:* `{part}`\n\nUse format: `limit:15`")
                                conn.close()
                                return
                    
                    queries.set_digest_preference(
                        conn, user_id=user_id, preference_name="default",
                        medical_flag=medical_flag,
                        ics_flag=ics_flag,
                        bio_keyword_flag=bio_keyword_flag,
                        kev_flag=kev_flag,
                        min_cvss=min_cvss,
                        min_bio_score=min_bio_score,
                        limit_count=limit_count,
                        enabled=True
                    )
                    
                    filters = []
                    if medical_flag:
                        filters.append("Medical devices")
                    if ics_flag:
                        filters.append("ICS/SCADA")
                    if bio_keyword_flag:
                        filters.append("Bio-keywords")
                    if kev_flag:
                        filters.append("CISA KEV")
                    if min_cvss:
                        filters.append(f"CVSS ≥ {min_cvss}")
                    if min_bio_score:
                        filters.append(f"Bio-score ≥ {min_bio_score}")
                    
                    response = f"""*Digest Preferences Updated*

*Limit:* {limit_count} vulnerabilities
*Filters:* {', '.join(filters) if filters else 'None (all vulnerabilities)'}

Your personalized digest will use these filters starting with the next scheduled run.

Use `/bioisac digest-setup show` to view your preferences"""
                    respond(response)
                
                elif action == "disable":
                    queries.set_digest_preference(conn, user_id=user_id, enabled=False)
                    respond("*Digest Preferences Disabled*\n\nYou will receive the default digest. Use `/bioisac digest-setup set` to re-enable custom filters.")
                
                else:
                    respond(f"*Unknown action:* `{action}`\n\nUse `/bioisac digest-setup` for help")
                
                conn.close()
            except Exception as e:
                try:
                    conn.close()
                except:
                    pass
                respond(f"*Error:* Failed to update preferences\n\n_Contact your administrator_")
                logger.error("Error in digest-setup command: %s", e)
            return
        
        # Admin commands
        if text.startswith("admin"):
            parts = text.split()
            
            # Check if user is admin
            if not is_admin(user_id):
                respond("*Access Denied:* Admin commands require administrator privileges.\n\n_Contact your Bio-ISAC administrator if you need admin access._")
                return
            
            if len(parts) < 2:
                admin_help = """*Bio-ISAC Admin Commands*

*USER MANAGEMENT*

`/bioisac admin add-user <user_id>`
Add a user to ALLOWED_USERS (grants bot access)
• Example: `/bioisac admin add-user U01234ABC`

`/bioisac admin remove-user <user_id>`
Remove a user from ALLOWED_USERS (revokes bot access)
• Example: `/bioisac admin remove-user U01234ABC`

`/bioisac admin list-users`
List all currently authorized users

`/bioisac admin sync-channel`
Sync all members of the Bio-ISAC channel to ALLOWED_USERS

────────────────────────────────

*CONFIGURATION*

These commands require `HEROKU_API_KEY` and `HEROKU_APP_NAME` environment variables.

*Auto-Add:* Set `AUTO_ADD_CHANNEL_MEMBERS=true` to automatically add new channel members.

────────────────────────────────

_Admin access is controlled via the `ADMIN_USERS` environment variable._"""
                respond(admin_help)
                return
            
            admin_action = parts[1].lower()
            
            # Add user command
            if admin_action == "add-user":
                if len(parts) < 3:
                    respond("*Usage:* `/bioisac admin add-user <user_id>`\n\n_Example:_ `/bioisac admin add-user U01234ABC`")
                    return
                
                target_user = parts[2].upper()
                if not target_user.startswith("U"):
                    respond(f"*Invalid User ID:* `{target_user}`\n\nSlack user IDs start with 'U' (e.g., U01234ABC)")
                    return
                
                success, message = add_user_to_allowed(target_user)
                if success:
                    respond(f"✅ *Success:* {message}\n\n_Heroku will automatically restart with updated permissions._")
                else:
                    respond(f"❌ *Error:* {message}")
                return
            
            # Remove user command
            if admin_action == "remove-user":
                if len(parts) < 3:
                    respond("*Usage:* `/bioisac admin remove-user <user_id>`\n\n_Example:_ `/bioisac admin remove-user U01234ABC`")
                    return
                
                target_user = parts[2].upper()
                if not target_user.startswith("U"):
                    respond(f"*Invalid User ID:* `{target_user}`\n\nSlack user IDs start with 'U' (e.g., U01234ABC)")
                    return
                
                success, message = remove_user_from_allowed(target_user)
                if success:
                    respond(f"✅ *Success:* {message}\n\n_Heroku will automatically restart with updated permissions._")
                else:
                    respond(f"❌ *Error:* {message}")
                return
            
            # List users command
            if admin_action == "list-users":
                users = get_heroku_allowed_users()
                
                if not users:
                    respond("*ALLOWED_USERS:* No users configured (all users allowed)\n\n_Set HEROKU_API_KEY and HEROKU_APP_NAME to manage users._")
                    return
                
                # Try to get user details
                user_lines = []
                for uid in sorted(users):
                    try:
                        info = get_slack_user_info(app.client, uid)
                        name = info.get("real_name") or info.get("name", "Unknown")
                        user_lines.append(f"• `{uid}` - {name}")
                    except Exception:
                        user_lines.append(f"• `{uid}`")
                
                respond(f"*Authorized Users ({len(users)})*\n\n" + "\n".join(user_lines))
                return
            
            # Sync channel command
            if admin_action == "sync-channel":
                bioisac_channel = os.environ.get("BIOISAC_CHANNEL") or os.environ.get("DIGEST_CHANNEL")
                
                if not bioisac_channel:
                    respond("*Error:* No channel configured.\n\nSet `BIOISAC_CHANNEL` or `DIGEST_CHANNEL` environment variable.")
                    return
                
                respond(f"🔄 *Syncing channel* <#{bioisac_channel}>...\n\n_This may take a moment._")
                
                try:
                    # Get channel members
                    result = app.client.conversations_members(channel=bioisac_channel, limit=1000)
                    if not result.get("ok"):
                        respond(f"*Error:* Could not fetch channel members: {result.get('error')}")
                        return
                    
                    members = result.get("members", [])
                    
                    # Filter out bots
                    human_members = []
                    for mid in members:
                        info = get_slack_user_info(app.client, mid)
                        if not info.get("is_bot"):
                            human_members.append(mid)
                    
                    # Get current allowed users and merge
                    current = get_heroku_allowed_users()
                    new_users = set(human_members) - current
                    updated = current | set(human_members)
                    
                    if new_users:
                        if update_heroku_allowed_users(updated):
                            respond(f"✅ *Sync Complete*\n\n"
                                   f"• Added {len(new_users)} new users\n"
                                   f"• Total authorized: {len(updated)}\n\n"
                                   f"*New users:*\n" + "\n".join(f"• `{u}`" for u in sorted(new_users)) +
                                   f"\n\n_Heroku will automatically restart with updated permissions._")
                        else:
                            respond(f"❌ *Error:* Failed to update Heroku config vars.\n\nCheck HEROKU_API_KEY and HEROKU_APP_NAME.")
                    else:
                        respond(f"✅ *Already in sync*\n\n• {len(human_members)} channel members\n• All are already authorized")
                    
                except Exception as e:
                    respond(f"*Error:* Failed to sync channel: {e}")
                return
            
            respond(f"*Unknown admin command:* `{admin_action}`\n\nType `/bioisac admin` for help.")
            return
        
        # Unknown command
        respond("*Error:* Unrecognized command\n\nType `/bioisac help` to view available commands")

    handler = SocketModeHandler(app, os.environ["SLACK_APP_LEVEL_TOKEN"])
    try:
        handler.start()
    except KeyboardInterrupt:
        print("\nBot stopped by user. Exiting gracefully...")
    except Exception as e:
        print(f"Error running bot: {e}")
        raise


if __name__ == "__main__":
    main()
