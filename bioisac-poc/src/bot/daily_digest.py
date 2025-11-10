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
    conn.close()
    if not rows:
        message = "No high-priority vulnerabilities in the queue today."
    else:
        header = f"Bio-ISAC Daily Digest — Top {len(rows)} (last {hours}h)"
        message = f"{header}\n\n{render_message(rows, hint=True)}"
    client.chat_postMessage(channel=channel.strip(), text=message)


def main():
    post_daily_digest()


if __name__ == "__main__":
    main()
