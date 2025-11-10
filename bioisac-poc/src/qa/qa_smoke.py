"""Lightweight smoke test for DB and Slack credentials."""
from __future__ import annotations

import os

from slack_sdk import WebClient

from ..etl import queries


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


def check_slack():
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    resp = client.auth_test()
    return resp.get("user_id"), resp.get("team")


def main():
    check_env()
    count = check_db()
    user_id, team = check_slack()
    print(f"DB OK. vulns rows={count}. Slack bot user={user_id}, team={team}")


if __name__ == "__main__":
    main()
