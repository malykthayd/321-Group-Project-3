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


def format_vuln(row: dict, position: Optional[int] = None) -> str:
    labels = []
    if row.get("cvss_base"):
        labels.append(f"CVSS {row['cvss_base']:.1f}")
    elif row.get("severity"):
        labels.append(row["severity"].title())
    labels.extend(row.get("category_labels", []))
    header_labels = " | ".join(labels) if labels else "No score"
    prefix = f"{position}) " if position is not None else ""
    header = f"{prefix}{row['cve_id']} ({header_labels}) — {_format_vendor_device(row)}"
    summary = row.get("plain_summary") or (row.get("description") or "")[:200]
    if summary and not summary.endswith("."):
        summary = summary.rstrip(".") + "."
    safe_action = row.get("safe_action") or "Review details and assess patch priority."
    advisory = row.get("advisory_url")
    lines = [
        header,
        f"• {summary}" if summary else "• No summary available.",
        f"• Safe next step: {safe_action}",
    ]
    if advisory:
        lines.append(f"Link: {advisory}")
    sources = ", ".join(row.get("source_list", []))
    if sources:
        lines.append(f"Sources: {sources}")
    return "\n".join(lines)


def render_message(rows: Iterable[dict], hint: bool = False) -> str:
    entries = [format_vuln(row, idx + 1) for idx, row in enumerate(rows)]
    body = "\n\n".join(entries)
    if hint:
        body = f"{body}\n\nTry: /bioisac top 5 | /bioisac search illumina"
    return body


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
            respond("You are not authorized to use this command.")
            return
        if text.startswith("top"):
            parts = text.split()
            limit = 5
            if len(parts) >= 2 and parts[1].isdigit():
                limit = int(parts[1])
            conn = queries.get_connection()
            rows = queries.get_top_vulns(conn, limit=limit)
            conn.close()
            if not rows:
                respond("No vulnerabilities available yet.")
                return
            respond(render_message(rows, hint=True))
            return
        if text.startswith("search"):
            term = text.partition(" ")[2].strip()
            if not term:
                respond("Usage: /bioisac search <keyword>")
                return
            conn = queries.get_connection()
            rows = queries.search_vulns(conn, term)
            conn.close()
            if not rows:
                respond(f"No results for '{term}'.")
                return
            respond(render_message(rows, hint=False))
            return
        respond("Commands: /bioisac top [n], /bioisac search <keyword>")

    SocketModeHandler(app, os.environ["SLACK_APP_LEVEL_TOKEN"]).start()


if __name__ == "__main__":
    main()
