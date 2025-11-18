"""Post the daily digest to a configured Slack channel."""
from __future__ import annotations

import os

from slack_sdk import WebClient

from ..etl import queries
from .bot import load_env, render_message


def format_digest_message(rows: list, hours: int, recent_count: int, kev_count: int, 
                          custom_filters: str = "") -> str:
    """Format digest message with optional custom filter description."""
    from datetime import datetime
    
    if not rows:
        message = f"""*Bio-ISAC Daily Security Digest*
_Automated Vulnerability Intelligence Report_

────────────────────────────────────────

*EXECUTIVE SUMMARY*

No high-priority vulnerabilities require immediate attention at this time.

*MONITORING PERIOD:* Last {hours} hours
*TOTAL MONITORED:* {recent_count} vulnerabilities
*HIGH-PRIORITY ITEMS:* 0
*KNOWN EXPLOITED (KEV):* {kev_count}
{custom_filters}

────────────────────────────────────────

The Bio-ISAC intelligence platform continues active monitoring of vulnerability feeds and threat intelligence sources. This digest is generated using automated bio-relevance scoring algorithms tailored to bio-industry infrastructure.

_For detailed analysis, use `/bioisac stats` or `/bioisac help` for available commands_"""
    else:
        header = f"""*Bio-ISAC Daily Security Digest*
_Automated Vulnerability Intelligence Report_

────────────────────────────────────────

*EXECUTIVE SUMMARY*

{len(rows)} high-priority vulnerabilities identified in the last {hours} hours requiring security team review.

*MONITORING PERIOD:* Last {hours} hours
*TOTAL NEW/UPDATED:* {recent_count} vulnerabilities
*REQUIRING ATTENTION:* {len(rows)} high-priority items
*KNOWN EXPLOITED (KEV):* {kev_count}
{custom_filters}

────────────────────────────────────────

*PRIORITY VULNERABILITIES*

"""
        
        footer = f"""

────────────────────────────────────────

*RECOMMENDED RESPONSE PROTOCOL*

1. Review each vulnerability for environmental applicability
2. Verify vendor advisory status and patch availability
3. Implement recommended mitigations per risk assessment
4. Document response actions and any justified exceptions

*ADDITIONAL ANALYSIS TOOLS*

`/bioisac detail <CVE-ID>` — Detailed vulnerability intelligence
`/bioisac search <keyword>` — Vendor/product-specific queries
`/bioisac stats` — Comprehensive database metrics
`/bioisac help` — Complete command reference

────────────────────────────────────────

_This automated digest employs bio-relevance scoring algorithms calibrated for bio-industry infrastructure. Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}_

*Bio-ISAC* — Advancing biosecurity through collaborative threat intelligence"""
        
        message = header + render_message(rows, hint=False) + footer
    
    return message


def post_daily_digest(limit: int = 10, use_preferences: bool = True) -> None:
    """Post daily digest with support for personalized preferences.
    
    Args:
        limit: Default limit if no preferences are set
        use_preferences: If True, send personalized digests to users/channels with preferences
    """
    load_env()
    try:
        client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    except KeyError:
        raise RuntimeError("SLACK_BOT_TOKEN not set in environment")
    
    hours = int(os.environ.get("DIGEST_LOOKBACK_HOURS", "24"))
    
    try:
        conn = queries.get_connection()
    except Exception as e:
        raise RuntimeError(f"Failed to connect to database: {e}")
    
    # Get stats for the digest (used by all digests)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as total FROM tags WHERE last_seen >= (NOW() - INTERVAL %s HOUR)", (hours,))
    recent_count = cursor.fetchone()["total"]
    
    cursor.execute("""
        SELECT SUM(kev_flag) as kev_count
        FROM tags 
        WHERE last_seen >= (NOW() - INTERVAL %s HOUR)
    """, (hours,))
    kev_result = cursor.fetchone()
    kev_count = kev_result["kev_count"] or 0
    cursor.close()
    
    if use_preferences:
        # Get all enabled preferences
        preferences = queries.get_all_digest_preferences(conn, enabled_only=True)
        
        # Send personalized digests
        for pref in preferences:
            try:
                # Build filter description
                filter_parts = []
                if pref.get("medical_flag"):
                    filter_parts.append("Medical devices")
                if pref.get("ics_flag"):
                    filter_parts.append("ICS/SCADA")
                if pref.get("bio_keyword_flag"):
                    filter_parts.append("Bio-keywords")
                if pref.get("kev_flag"):
                    filter_parts.append("CISA KEV")
                if pref.get("min_cvss"):
                    filter_parts.append(f"CVSS ≥ {pref['min_cvss']}")
                if pref.get("min_bio_score"):
                    filter_parts.append(f"Bio-score ≥ {pref['min_bio_score']}")
                
                custom_filters = f"*FILTERS:* {', '.join(filter_parts)}\n" if filter_parts else ""
                
                # Get filtered digest
                rows = queries.get_digest(
                    conn,
                    limit=pref.get("limit_count", limit),
                    hours=hours,
                    medical_flag=pref.get("medical_flag"),
                    ics_flag=pref.get("ics_flag"),
                    bio_keyword_flag=pref.get("bio_keyword_flag"),
                    kev_flag=pref.get("kev_flag"),
                    min_cvss=pref.get("min_cvss"),
                    min_bio_score=pref.get("min_bio_score")
                )
                
                message = format_digest_message(rows, hours, recent_count, kev_count, custom_filters)
                
                # Send to user (DM) or channel
                target = pref.get("slack_user_id") or pref.get("slack_channel_id")
                if target:
                    try:
                        client.chat_postMessage(channel=target.strip(), text=message)
                    except Exception as e:
                        # Log but continue with other preferences
                        print(f"Failed to send digest to {target}: {e}")
            except Exception as e:
                # Log but continue with other preferences
                print(f"Error processing preference {pref.get('id')}: {e}")
        
        conn.close()
        
        # Also send default digest to default channel if configured
        default_channel = os.environ.get("DIGEST_CHANNEL") or os.environ.get("ALLOWED_CHANNELS", "").split(",")[0]
        if default_channel:
            try:
                conn = queries.get_connection()
                rows = queries.get_digest(conn, limit=limit, hours=hours)
                message = format_digest_message(rows, hours, recent_count, kev_count)
                conn.close()
                client.chat_postMessage(channel=default_channel.strip(), text=message)
            except Exception as e:
                print(f"Failed to send default digest: {e}")
    else:
        # Legacy behavior: send to default channel only
        channel = os.environ.get("DIGEST_CHANNEL") or os.environ.get("ALLOWED_CHANNELS", "").split(",")[0]
        if not channel:
            conn.close()
            raise RuntimeError("DIGEST_CHANNEL not set")
        
        try:
            rows = queries.get_digest(conn, limit=limit, hours=hours)
        except Exception as e:
            conn.close()
            raise RuntimeError(f"Failed to fetch digest data: {e}")
        
        message = format_digest_message(rows, hours, recent_count, kev_count)
        
        try:
            client.chat_postMessage(channel=channel.strip(), text=message)
        except Exception as e:
            conn.close()
            raise RuntimeError(f"Failed to post message to Slack: {e}")
        
        conn.close()


def main():
    post_daily_digest()


if __name__ == "__main__":
    main()
