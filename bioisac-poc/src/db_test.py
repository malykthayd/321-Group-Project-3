"""Run schema migrations and basic connectivity checks."""
from __future__ import annotations

import os
from pathlib import Path

import mysql.connector

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def load_env() -> None:
    if os.getenv("ENV_LOADED"):
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    dotenv_path = Path(__file__).resolve().parents[1] / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path)


def get_connection():
    load_env()
    config = {
        "host": os.environ.get("DB_HOST"),
        "user": os.environ.get("DB_USER"),
        "password": os.environ.get("DB_PASS"),
        "database": os.environ.get("DB_NAME"),
        "port": int(os.environ.get("DB_PORT", "3306")),
    }
    missing = [key for key, value in config.items() if value in (None, "") and key != "port"]
    if missing:
        raise RuntimeError(f"Missing database configuration: {', '.join(missing)}")
    return mysql.connector.connect(**config)


def apply_schema(cursor) -> None:
    with SCHEMA_PATH.open("r", encoding="utf-8") as f:
        schema_sql = f.read()
    for statement in schema_sql.split(";\n"):
        stmt = statement.strip()
        if stmt:
            cursor.execute(stmt)


def main() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    apply_schema(cursor)
    conn.commit()
    cursor.execute("SELECT COUNT(*) FROM vulns")
    (count,) = cursor.fetchone()
    print(f"Connected. vulns rows: {count}")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()
