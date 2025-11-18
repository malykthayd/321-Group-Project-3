"""Run schema migrations and basic connectivity checks."""
from __future__ import annotations

from pathlib import Path

from .etl import queries

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def apply_schema(cursor) -> None:
    with SCHEMA_PATH.open("r", encoding="utf-8") as f:
        schema_sql = f.read()
    for statement in schema_sql.split(";\n"):
        stmt = statement.strip()
        if stmt:
            cursor.execute(stmt)


def main() -> None:
    conn = queries.get_connection()
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
