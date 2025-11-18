"""Database helper functions shared across ETL and Slack bot."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import mysql.connector


_ENV_LOADED = False


def load_env_once() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        _ENV_LOADED = True
        return
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    _ENV_LOADED = True


def get_connection():
    load_env_once()
    
    # Prefer JAWSDB URLs if available (Heroku addon)
    # Prioritize upgraded JAWSDB_URL (leopard plan) over free tier instances
    jawsdb_url = os.environ.get("JAWSDB_URL")  # Standard/upgraded JAWSDB_URL (preferred)
    if not jawsdb_url:
        # Fall back to other JAWSDB instances (JAWSDB_AMBER_URL, etc.)
        for key in os.environ:
            if key.startswith("JAWSDB_") and key.endswith("_URL") and key != "JAWSDB_URL":
                jawsdb_url = os.environ.get(key)
                break
    if jawsdb_url:
        # Parse JAWSDB_URL format: mysql://user:password@host:port/database
        try:
            # Remove mysql:// prefix
            url = jawsdb_url.replace("mysql://", "")
            # Split into user:pass@host:port/db
            if "@" in url:
                auth_part, rest = url.split("@", 1)
                user, password = auth_part.split(":", 1)
                if "/" in rest:
                    host_port, database = rest.split("/", 1)
                else:
                    host_port = rest
                    database = ""
                if ":" in host_port:
                    host, port = host_port.split(":", 1)
                    port = int(port)
                else:
                    host = host_port
                    port = 3306
                
                config = {
                    "host": host,
                    "user": user,
                    "password": password,
                    "database": database,
                    "port": port,
                }
            else:
                raise ValueError("Invalid JAWSDB_URL format")
        except (ValueError, AttributeError) as e:
            raise RuntimeError(f"Failed to parse JAWSDB_URL: {e}")
    else:
        # Fall back to individual environment variables
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
    
    try:
        return mysql.connector.connect(**config)
    except mysql.connector.Error as e:
        raise RuntimeError(f"Database connection failed: {e}")


def init_db(conn) -> None:
    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    cursor = conn.cursor()
    for statement in schema_sql.split(";\n"):
        stmt = statement.strip()
        if stmt:
            cursor.execute(stmt)
    cursor.close()
    conn.commit()


def upsert_vuln(conn, record: Dict[str, Any]) -> None:
    fields = [
        "cve_id",
        "title",
        "description",
        "cvss_base",
        "cvss_vector",
        "severity",
        "published",
        "last_modified",
        "vendor",
        "product",
        "source_list",
        "euvd_notes",
        "advisory_url",
        "plain_summary",
        "safe_action",
    ]
    payload = {field: record.get(field) for field in fields}
    payload["source_list"] = json.dumps(sorted(set(record.get("source_list", [])))) if record.get("source_list") else None
    sql = (
        "INSERT INTO vulns (cve_id, title, description, cvss_base, cvss_vector, severity, published, "
        "last_modified, vendor, product, source_list, euvd_notes, advisory_url, plain_summary, safe_action) "
        "VALUES (%(cve_id)s, %(title)s, %(description)s, %(cvss_base)s, %(cvss_vector)s, %(severity)s, "
        "%(published)s, %(last_modified)s, %(vendor)s, %(product)s, %(source_list)s, %(euvd_notes)s, "
        "%(advisory_url)s, %(plain_summary)s, %(safe_action)s) "
        "ON DUPLICATE KEY UPDATE title=VALUES(title), description=VALUES(description), cvss_base=VALUES(cvss_base),"
        " cvss_vector=VALUES(cvss_vector), severity=VALUES(severity), published=VALUES(published),"
        " last_modified=VALUES(last_modified), vendor=VALUES(vendor), product=VALUES(product),"
        " source_list=VALUES(source_list), euvd_notes=VALUES(euvd_notes), advisory_url=VALUES(advisory_url),"
        " plain_summary=VALUES(plain_summary), safe_action=VALUES(safe_action)"
    )
    cursor = conn.cursor()
    cursor.execute(sql, payload)
    conn.commit()
    cursor.close()


def upsert_tag(conn, tag: Dict[str, Any]) -> None:
    sql = (
        "INSERT INTO tags (cve_id, kev_flag, ics_flag, medical_flag, bio_keyword_flag, recent_flag, cvss_high_flag,"
        " bio_score, source_count, confidence_level, conflict_flag, category_labels, notes) "
        "VALUES (%(cve_id)s, %(kev_flag)s, %(ics_flag)s, %(medical_flag)s, %(bio_keyword_flag)s, %(recent_flag)s,"
        " %(cvss_high_flag)s, %(bio_score)s, %(source_count)s, %(confidence_level)s, %(conflict_flag)s, "
        "%(category_labels)s, %(notes)s) "
        "ON DUPLICATE KEY UPDATE kev_flag=VALUES(kev_flag), ics_flag=VALUES(ics_flag),"
        " medical_flag=VALUES(medical_flag), bio_keyword_flag=VALUES(bio_keyword_flag),"
        " recent_flag=VALUES(recent_flag), cvss_high_flag=VALUES(cvss_high_flag), bio_score=VALUES(bio_score),"
        " source_count=VALUES(source_count), confidence_level=VALUES(confidence_level),"
        " conflict_flag=VALUES(conflict_flag), category_labels=VALUES(category_labels),"
        " notes=VALUES(notes), last_seen=CURRENT_TIMESTAMP"
    )
    cursor = conn.cursor()
    payload = tag.copy()
    payload["category_labels"] = json.dumps(sorted(set(tag.get("category_labels", [])))) if tag.get("category_labels") else None
    cursor.execute(sql, payload)
    conn.commit()
    cursor.close()


def get_top_vulns(conn, limit: int = 5) -> List[Dict[str, Any]]:
    sql = (
        "SELECT v.*, t.bio_score, t.confidence_level, t.kev_flag, t.ics_flag, t.medical_flag,"
        " t.bio_keyword_flag, t.recent_flag, t.cvss_high_flag, t.source_count, t.conflict_flag, t.category_labels "
        "FROM vulns v JOIN tags t ON v.cve_id = t.cve_id "
        "ORDER BY t.bio_score DESC, v.cvss_base DESC, v.published DESC LIMIT %s"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, (limit,))
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        row["source_list"] = json.loads(row["source_list"]) if row.get("source_list") else []
        row["category_labels"] = json.loads(row["category_labels"]) if row.get("category_labels") else []
    return rows


def search_vulns(conn, term: str, limit: int = 20) -> List[Dict[str, Any]]:
    like_term = f"%{term}%"
    sql = (
        "SELECT v.*, t.bio_score, t.confidence_level, t.kev_flag, t.ics_flag, t.medical_flag,"
        " t.bio_keyword_flag, t.recent_flag, t.cvss_high_flag, t.source_count, t.conflict_flag, t.category_labels "
        "FROM vulns v JOIN tags t ON v.cve_id = t.cve_id "
        "WHERE v.cve_id LIKE %s OR v.vendor LIKE %s OR v.product LIKE %s OR v.title LIKE %s "
        "ORDER BY t.bio_score DESC, v.published DESC LIMIT %s"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, (like_term, like_term, like_term, like_term, limit))
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        row["source_list"] = json.loads(row["source_list"]) if row.get("source_list") else []
        row["category_labels"] = json.loads(row["category_labels"]) if row.get("category_labels") else []
    return rows


def get_recent_vulns(conn, hours: int = 24, limit: int = 5) -> List[Dict[str, Any]]:
    sql = (
        "SELECT v.*, t.bio_score, t.confidence_level, t.kev_flag, t.ics_flag, t.medical_flag,"
        " t.bio_keyword_flag, t.recent_flag, t.cvss_high_flag, t.source_count, t.conflict_flag, t.category_labels "
        "FROM vulns v JOIN tags t ON v.cve_id = t.cve_id "
        "WHERE t.last_seen >= (NOW() - INTERVAL %s HOUR) "
        "ORDER BY t.last_seen DESC, t.bio_score DESC LIMIT %s"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, (hours, limit))
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        row["source_list"] = json.loads(row["source_list"]) if row.get("source_list") else []
        row["category_labels"] = json.loads(row["category_labels"]) if row.get("category_labels") else []
    return rows


def get_digest(conn, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
    rows = get_recent_vulns(conn, hours=hours, limit=limit)
    return rows or get_top_vulns(conn, limit=limit)


def get_example_data(conn) -> Dict[str, Optional[str]]:
    """Get example CVE ID and search keyword from database for help text."""
    cursor = conn.cursor(dictionary=True)
    
    # Get a real CVE ID (prefer one with high bio score for better demo)
    cursor.execute("""
        SELECT v.cve_id FROM vulns v 
        JOIN tags t ON v.cve_id = t.cve_id 
        ORDER BY t.bio_score DESC, v.published DESC LIMIT 1
    """)
    cve_result = cursor.fetchone()
    example_cve = cve_result["cve_id"] if cve_result else None
    
    # Get a real vendor or product for search example
    # Get vendors that appear frequently for better search results
    cursor.execute("""
        SELECT vendor FROM vulns 
        WHERE vendor IS NOT NULL AND vendor != '' AND LENGTH(vendor) >= 3
        GROUP BY vendor
        HAVING COUNT(*) >= 1
        ORDER BY COUNT(*) DESC, vendor ASC
        LIMIT 20
    """)
    vendor_results = cursor.fetchall()
    example_keyword = None
    
    # Try to find a good vendor keyword
    for row in vendor_results:
        vendor = row["vendor"].strip()
        if not vendor:
            continue
        # Use first word if multi-word, or full vendor if single word
        words = vendor.split()
        candidate = words[0].lower() if len(words) > 1 else vendor.lower()
        # Skip very short or generic terms
        if len(candidate) >= 3 and candidate not in ['the', 'and', 'for', 'inc', 'ltd', 'corp', 'llc']:
            example_keyword = candidate
            break
    
    # If no good vendor, try products
    if not example_keyword:
        cursor.execute("""
            SELECT product FROM vulns 
            WHERE product IS NOT NULL AND product != '' AND LENGTH(product) >= 3
            GROUP BY product
            HAVING COUNT(*) >= 1
            ORDER BY COUNT(*) DESC, product ASC
            LIMIT 20
        """)
        product_results = cursor.fetchall()
        for row in product_results:
            product = row["product"].strip()
            if not product:
                continue
            words = product.split()
            candidate = words[0].lower() if len(words) > 1 else product.lower()
            if len(candidate) >= 3 and candidate not in ['the', 'and', 'for', 'inc', 'ltd', 'corp', 'llc']:
                example_keyword = candidate
                break
    
    cursor.close()
    return {
        "cve_id": example_cve,
        "search_keyword": example_keyword or "vulnerability"
    }
