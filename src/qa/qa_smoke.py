"""Lightweight smoke test for DB and Slack credentials."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

from slack_sdk import WebClient

from ..etl import queries


def load_env() -> None:
    """Load environment variables from .env file if it exists."""
    if os.environ.get("ENV_LOADED"):
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    os.environ["ENV_LOADED"] = "1"


REQUIRED_ENV = [
    "SLACK_BOT_TOKEN",
    "SLACK_APP_LEVEL_TOKEN",
    "ALLOWED_USERS",
    "ALLOWED_CHANNELS",
    "DB_HOST",
    "DB_USER",
    "DB_PASS",
    "DB_NAME",
]


def check_env():
    missing = [key for key in REQUIRED_ENV if not os.environ.get(key)]
    if missing:
        raise SystemExit(f"Missing env vars: {', '.join(missing)}")


def check_db():
    conn = queries.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM vulns")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count


def parse_allow_list(value: str) -> List[str]:
    """Parse comma-separated allow list."""
    return [item.strip() for item in value.split(",") if item.strip()]


def check_slack():
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    resp = client.auth_test()
    bot_user_id = resp.get("user_id")
    team = resp.get("team")
    
    # Get configured allowed users and channels
    allowed_users = parse_allow_list(os.environ.get("ALLOWED_USERS", ""))
    allowed_channels = parse_allow_list(os.environ.get("ALLOWED_CHANNELS", ""))
    
    return bot_user_id, team, allowed_users, allowed_channels


def main():
    load_env()
    check_env()
    count = check_db()
    bot_user_id, team, allowed_users, allowed_channels = check_slack()
    
    print(f"DB OK. vulns rows={count}")
    print(f"Slack bot user={bot_user_id}, team={team}")
    if allowed_users:
        print(f"Allowed users ({len(allowed_users)}): {', '.join(allowed_users)}")
    else:
        print("Allowed users: (none - all users allowed)")
    if allowed_channels:
        print(f"Allowed channels ({len(allowed_channels)}): {', '.join(allowed_channels)}")
    else:
        print("Allowed channels: (none - all channels allowed)")


if __name__ == "__main__":
    main()
