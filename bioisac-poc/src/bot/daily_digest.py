"""Post the daily digest to a configured Slack channel."""
from __future__ import annotations

import os

from slack_sdk import WebClient

from ..etl import queries
from .bot import load_env, render_message


def post_daily_digest(limit: int = 5) -> None:
    load_env()
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    channel = os.environ.get("DIGEST_CHANNEL") or os.environ.get("ALLOWED_CHANNELS", "").split(",")[0]
    if not channel:
        raise RuntimeError("DIGEST_CHANNEL not set")
    hours = int(os.environ.get("DIGEST_LOOKBACK_HOURS", "24"))
    conn = queries.get_connection()
    rows = queries.get_digest(conn, limit=limit, hours=hours)
    
    # Get stats for the digest
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
    conn.close()
    
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

────────────────────────────────────────

The Bio-ISAC intelligence platform continues active monitoring of vulnerability feeds and threat intelligence sources. This digest is generated using automated bio-relevance scoring algorithms tailored to bio-industry infrastructure.

_For detailed analysis, use `/bioisac stats` or `/bioisac help` for available commands_"""
    else:
        from datetime import datetime
        
        header = f"""*Bio-ISAC Daily Security Digest*
_Automated Vulnerability Intelligence Report_

────────────────────────────────────────

*EXECUTIVE SUMMARY*

{len(rows)} high-priority vulnerabilities identified in the last {hours} hours requiring security team review.

*MONITORING PERIOD:* Last {hours} hours
*TOTAL NEW/UPDATED:* {recent_count} vulnerabilities
*REQUIRING ATTENTION:* {len(rows)} high-priority items
*KNOWN EXPLOITED (KEV):* {kev_count}

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
    
    client.chat_postMessage(channel=channel.strip(), text=message)


def main():
    post_daily_digest()


if __name__ == "__main__":
    main()
