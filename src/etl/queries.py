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
    # Check both updated_at (when data changed) and published (when CVE was published)
    # to catch both newly published CVEs and recently updated existing ones
    sql = (
        "SELECT v.*, t.bio_score, t.confidence_level, t.kev_flag, t.ics_flag, t.medical_flag,"
        " t.bio_keyword_flag, t.recent_flag, t.cvss_high_flag, t.source_count, t.conflict_flag, t.category_labels "
        "FROM vulns v JOIN tags t ON v.cve_id = t.cve_id "
        "WHERE (v.updated_at >= (NOW() - INTERVAL %s HOUR) "
        "   OR v.published >= DATE_SUB(CURDATE(), INTERVAL %s HOUR)) "
        "ORDER BY GREATEST(v.updated_at, COALESCE(CAST(v.published AS DATETIME), v.updated_at)) DESC, t.bio_score DESC LIMIT %s"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, (hours, hours, limit))
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        # Safely parse source_list
        source_list = row.get("source_list")
        if source_list:
            if isinstance(source_list, str):
                try:
                    row["source_list"] = json.loads(source_list)
                except (json.JSONDecodeError, TypeError):
                    row["source_list"] = []
            elif isinstance(source_list, (list, dict)):
                row["source_list"] = source_list
            else:
                row["source_list"] = []
        else:
            row["source_list"] = []
        
        # Safely parse category_labels
        category_labels = row.get("category_labels")
        if category_labels:
            if isinstance(category_labels, str):
                try:
                    row["category_labels"] = json.loads(category_labels)
                except (json.JSONDecodeError, TypeError):
                    row["category_labels"] = []
            elif isinstance(category_labels, (list, dict)):
                row["category_labels"] = category_labels
            else:
                row["category_labels"] = []
        else:
            row["category_labels"] = []
    return rows


def get_digest(conn, limit: int = 10, hours: int = 24, 
               medical_flag: Optional[bool] = None,
               ics_flag: Optional[bool] = None,
               bio_keyword_flag: Optional[bool] = None,
               kev_flag: Optional[bool] = None,
               min_cvss: Optional[float] = None,
               min_bio_score: Optional[int] = None) -> List[Dict[str, Any]]:
    """Get digest vulnerabilities with optional filtering."""
    # Use updated_at instead of last_seen to show new OR updated vulnerabilities
    # updated_at only changes when vulnerability data actually changes (CVSS, description, etc.)
    # last_seen gets updated every time ETL runs even if nothing changed, causing duplicates
    conditions = ["v.updated_at >= (NOW() - INTERVAL %s HOUR)"]
    params = [hours]
    
    if medical_flag is not None:
        conditions.append("t.medical_flag = %s")
        params.append(1 if medical_flag else 0)
    if ics_flag is not None:
        conditions.append("t.ics_flag = %s")
        params.append(1 if ics_flag else 0)
    if bio_keyword_flag is not None:
        conditions.append("t.bio_keyword_flag = %s")
        params.append(1 if bio_keyword_flag else 0)
    if kev_flag is not None:
        conditions.append("t.kev_flag = %s")
        params.append(1 if kev_flag else 0)
    if min_cvss is not None:
        conditions.append("v.cvss_base >= %s")
        params.append(min_cvss)
    if min_bio_score is not None:
        conditions.append("t.bio_score >= %s")
        params.append(min_bio_score)
    
    where_clause = " AND ".join(conditions)
    sql = (
        f"SELECT v.*, t.bio_score, t.confidence_level, t.kev_flag, t.ics_flag, t.medical_flag,"
        f" t.bio_keyword_flag, t.recent_flag, t.cvss_high_flag, t.source_count, t.conflict_flag, t.category_labels "
        f"FROM vulns v JOIN tags t ON v.cve_id = t.cve_id "
        f"WHERE {where_clause} "
        f"ORDER BY t.bio_score DESC, v.cvss_base DESC, v.published DESC LIMIT %s"
    )
    params.append(limit)
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    cursor.close()
    
    for row in rows:
        row["source_list"] = json.loads(row["source_list"]) if row.get("source_list") else []
        row["category_labels"] = json.loads(row["category_labels"]) if row.get("category_labels") else []
    
    # If no results with filters, fall back to top vulns (without filters)
    if not rows and any([medical_flag is not None, ics_flag is not None, bio_keyword_flag is not None, 
                        kev_flag is not None, min_cvss is not None, min_bio_score is not None]):
        return get_top_vulns(conn, limit=limit)
    
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


def get_digest_preference(conn, user_id: Optional[str] = None, channel_id: Optional[str] = None, 
                         preference_name: str = "default") -> Optional[Dict[str, Any]]:
    """Get digest preference for a user or channel."""
    cursor = conn.cursor(dictionary=True)
    if user_id:
        cursor.execute("""
            SELECT * FROM digest_preferences 
            WHERE slack_user_id = %s AND preference_name = %s AND enabled = 1
            ORDER BY updated_at DESC LIMIT 1
        """, (user_id, preference_name))
    elif channel_id:
        cursor.execute("""
            SELECT * FROM digest_preferences 
            WHERE slack_channel_id = %s AND preference_name = %s AND enabled = 1
            ORDER BY updated_at DESC LIMIT 1
        """, (channel_id, preference_name))
    else:
        cursor.close()
        return None
    
    result = cursor.fetchone()
    cursor.close()
    return result


def set_digest_preference(conn, user_id: Optional[str] = None, channel_id: Optional[str] = None,
                          preference_name: str = "default",
                          medical_flag: Optional[bool] = None,
                          ics_flag: Optional[bool] = None,
                          bio_keyword_flag: Optional[bool] = None,
                          kev_flag: Optional[bool] = None,
                          min_cvss: Optional[float] = None,
                          min_bio_score: Optional[int] = None,
                          limit_count: int = 10,
                          digest_time: Optional[str] = None,
                          enabled: bool = True) -> None:
    """Set or update digest preference for a user or channel."""
    cursor = conn.cursor()
    
    # Check if preference exists
    if user_id:
        cursor.execute("""
            SELECT id FROM digest_preferences 
            WHERE slack_user_id = %s AND preference_name = %s
        """, (user_id, preference_name))
    else:
        cursor.execute("""
            SELECT id FROM digest_preferences 
            WHERE slack_channel_id = %s AND preference_name = %s
        """, (channel_id, preference_name))
    
    existing = cursor.fetchone()
    
    # Convert boolean flags to integers (1/0) for MySQL TINYINT
    medical_flag_int = 1 if medical_flag else (0 if medical_flag is False else None)
    ics_flag_int = 1 if ics_flag else (0 if ics_flag is False else None)
    bio_keyword_flag_int = 1 if bio_keyword_flag else (0 if bio_keyword_flag is False else None)
    kev_flag_int = 1 if kev_flag else (0 if kev_flag is False else None)
    
    if existing:
        # Update existing - only update fields that are not None
        update_fields = []
        update_values = []
        
        if medical_flag is not None:
            update_fields.append("medical_flag = %s")
            update_values.append(medical_flag_int)
        if ics_flag is not None:
            update_fields.append("ics_flag = %s")
            update_values.append(ics_flag_int)
        if bio_keyword_flag is not None:
            update_fields.append("bio_keyword_flag = %s")
            update_values.append(bio_keyword_flag_int)
        if kev_flag is not None:
            update_fields.append("kev_flag = %s")
            update_values.append(kev_flag_int)
        if min_cvss is not None:
            update_fields.append("min_cvss = %s")
            update_values.append(min_cvss)
        if min_bio_score is not None:
            update_fields.append("min_bio_score = %s")
            update_values.append(min_bio_score)
        if limit_count is not None:
            update_fields.append("limit_count = %s")
            update_values.append(limit_count)
        if digest_time is not None:
            update_fields.append("digest_time = %s")
            update_values.append(digest_time)
        # Always update enabled and updated_at
        update_fields.append("enabled = %s")
        update_values.append(1 if enabled else 0)
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        
        if update_fields:
            update_values.append(existing[0])
            cursor.execute(f"""
                UPDATE digest_preferences SET
                    {', '.join(update_fields)}
                WHERE id = %s
            """, update_values)
    else:
        # Insert new
        cursor.execute("""
            INSERT INTO digest_preferences 
            (slack_user_id, slack_channel_id, preference_name, medical_flag, ics_flag, 
             bio_keyword_flag, kev_flag, min_cvss, min_bio_score, limit_count, digest_time, enabled)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, channel_id, preference_name, medical_flag_int, ics_flag_int, 
              bio_keyword_flag_int, kev_flag_int, min_cvss, min_bio_score, limit_count, digest_time, 1 if enabled else 0))
    
    conn.commit()
    cursor.close()


def get_all_digest_preferences(conn, enabled_only: bool = True) -> List[Dict[str, Any]]:
    """Get all digest preferences (for batch processing)."""
    cursor = conn.cursor(dictionary=True)
    if enabled_only:
        cursor.execute("SELECT * FROM digest_preferences WHERE enabled = 1")
    else:
        cursor.execute("SELECT * FROM digest_preferences")
    results = cursor.fetchall()
    cursor.close()
    return results
