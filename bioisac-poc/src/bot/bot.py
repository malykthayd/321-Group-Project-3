"""Slack Bolt app for Bio-ISAC vulnerability triage."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional

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
    """Return a clean severity badge based on CVSS score."""
    cvss = row.get("cvss_base")
    if cvss:
        if cvss >= 9.0:
            return "▪️ CRITICAL"
        elif cvss >= 7.0:
            return "▪️ HIGH"
        elif cvss >= 4.0:
            return "▪️ MEDIUM"
        else:
            return "▪️ LOW"
    severity = row.get("severity", "").upper()
    if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        return f"▪️ {severity}"
    return "▪️ UNRATED"


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
    header = f"{prefix}*{row['cve_id']}*  {severity_badge}"
    
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
    
    # Advisory link
    advisory = row.get("advisory_url")
    if advisory:
        lines.append(f"\n*Advisory:* <{advisory}|View Details>")
    
    # Metadata footer
    metadata = []
    sources = ", ".join(row.get("source_list", []))
    if sources:
        metadata.append(f"Sources: {sources}")
    
    bio_score = row.get("bio_score")
    if bio_score is not None:
        metadata.append(f"Bio-Relevance: {bio_score}/100")
    
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
    return "*Access Denied:* Authorization required\n\n_Contact your Bio-ISAC administrator for access permissions_"


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
            help_text = """*Bio-ISAC Vulnerability Intelligence Platform*

*AVAILABLE COMMANDS*

`/bioisac help`
Display this help documentation

`/bioisac top [n]`
Retrieve top N vulnerabilities ranked by bio-relevance score
Default: 5 vulnerabilities

`/bioisac search <keyword>`
Search vulnerability database by CVE ID, vendor, product, or title
Example: `/bioisac search illumina`

`/bioisac recent [hours]`
Display vulnerabilities discovered within specified timeframe
Default: 24 hours

`/bioisac stats`
View comprehensive vulnerability statistics and metrics

`/bioisac detail <CVE-ID>`
Retrieve detailed information for a specific CVE identifier
Example: `/bioisac detail CVE-2024-1234`

────────────────────────────────

*PRIORITY INDICATORS*

`KEV` - CISA Known Exploited Vulnerability
`MEDICAL` - Medical device related
`ICS` - Industrial Control System
`BIO-RELEVANT` - Bio-industry keyword match

*SEVERITY CLASSIFICATION*

▪️ CRITICAL - CVSS 9.0-10.0
▪️ HIGH - CVSS 7.0-8.9
▪️ MEDIUM - CVSS 4.0-6.9
▪️ LOW - CVSS 0.1-3.9

────────────────────────────────

_For technical support, contact your Bio-ISAC security administrator_"""
            respond(help_text)
            return
        
        # Top command
        if text.startswith("top"):
            parts = text.split()
            limit = 5
            if len(parts) >= 2 and parts[1].isdigit():
                limit = int(parts[1])
            conn = queries.get_connection()
            rows = queries.get_top_vulns(conn, limit=limit)
            conn.close()
            if not rows:
                respond(format_no_results_message(
                    "Database Query",
                    "Top vulnerabilities",
                    "Database may be empty. Run ETL process to populate vulnerability data."
                ))
                return
            
            # Apply pagination to prevent overwhelming messages
            display_rows, truncation_footer = apply_pagination(
                rows,
                f"Use `/bioisac search <keyword>` to filter by vendor or product"
            )
            
            header = f"*Top {len(display_rows)} Vulnerabilities — Ranked by Bio-Relevance*\n\n"
            respond(header + render_message(display_rows, hint=True) + truncation_footer)
            return
        
        # Search command
        if text.startswith("search"):
            term = text.partition(" ")[2].strip()
            if not term:
                respond("*Usage:* `/bioisac search <keyword>`\n\n_Example:_ `/bioisac search illumina`")
                return
            conn = queries.get_connection()
            rows = queries.search_vulns(conn, term)
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
            
            conn = queries.get_connection()
            rows = queries.get_recent_vulns(conn, hours=hours, limit=20)
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
            return
        
        # Stats command
        if text == "stats":
            conn = queries.get_connection()
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
            
            conn = queries.get_connection()
            rows = queries.search_vulns(conn, cve_id)
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
        
        # Unknown command
        respond("*Error:* Unrecognized command\n\nType `/bioisac help` to view available commands")

    SocketModeHandler(app, os.environ["SLACK_APP_LEVEL_TOKEN"]).start()


if __name__ == "__main__":
    main()
