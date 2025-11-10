"""ETL entrypoint: fetch, normalize, score, and load vulnerabilities."""
from __future__ import annotations

import datetime as dt
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from . import queries

try:
    import requests  # type: ignore[import]
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

try:
    from dotenv import load_dotenv  # type: ignore[import]
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

_ENV_READY = False


def load_env() -> None:
    global _ENV_READY
    if _ENV_READY:
        return
    if load_dotenv:
        env_path = Path(__file__).resolve().parents[2] / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    _ENV_READY = True


load_env()

LOG_DIR = Path(__file__).resolve().parents[2] / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "etl.log"

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# Placeholder keywords; expand as needed.
ICS_KEYWORDS = {"industrial control", "ics", "scada", "plc", "rtu", "controller"}
MEDICAL_KEYWORDS = {"medical", "clinical", "healthcare", "hospital", "biomedical", "diagnostic"}
BIO_KEYWORDS = {"sequencer", "bioreactor", "incubator", "centrifuge", "pipette", "lab", "dna", "genomics"}


def fetch_nvd_items(since: dt.datetime) -> List[Dict]:
    """Fetch CVE items from NVD CVE 2.0 API."""
    if requests is None:
        raise RuntimeError("requests package not available; install from requirements.txt")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
    }
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    logger.info("Requesting NVD with params %s", params)
    response = requests.get(base_url, params=params, headers=headers, timeout=60)
    logger.info("NVD request status %s", response.status_code)
    response.raise_for_status()
    data = response.json()
    total_results = data.get("totalResults")
    if total_results is not None:
        logger.info("NVD total results: %s", total_results)
    return data.get("vulnerabilities", [])


def fetch_kev_items() -> List[Dict]:
    import csv
    import io
    if requests is None:
        raise RuntimeError("requests package not available; install from requirements.txt")

    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    text_stream = io.StringIO(response.text)
    reader = csv.DictReader(text_stream)
    return list(reader)


def _extract_vendor_product(cve: Dict) -> tuple[Optional[str], Optional[str]]:
    vendor = None
    product = None
    configurations = cve.get("configurations") or {}
    nodes: List[Dict] = []
    if isinstance(configurations, list):
        for config in configurations:
            if isinstance(config, dict):
                nodes.extend(config.get("nodes", []))
    elif isinstance(configurations, dict):
        nodes = configurations.get("nodes", []) or []
    for node in nodes:
        matches = node.get("cpeMatch") or []
        for match in matches:
            cpe23 = match.get("criteria")
            if not cpe23:
                continue
            parts = cpe23.split(":")
            if len(parts) >= 5:
                vendor = parts[3] or vendor
                product = parts[4] or product
            if vendor and product:
                break
        if vendor and product:
            break
    return vendor, product


def _extract_advisory_url(cve: Dict) -> Optional[str]:
    refs = cve.get("references", [])
    for ref in refs:
        tags = ref.get("tags") or []
        if "Vendor Advisory" in tags:
            return ref.get("url")
    return refs[0].get("url") if refs else None


def normalize_nvd(item: Dict) -> Dict:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    cvss = None
    severity = None
    vector = None
    if "cvssMetricV31" in metrics:
        metric = metrics["cvssMetricV31"][0]
        cvss = metric["cvssData"].get("baseScore")
        severity = metric.get("baseSeverity")
        vector = metric["cvssData"].get("vectorString")
    elif "cvssMetricV30" in metrics:
        metric = metrics["cvssMetricV30"][0]
        cvss = metric["cvssData"].get("baseScore")
        severity = metric.get("baseSeverity")
        vector = metric["cvssData"].get("vectorString")
    desc = ""
    if cve.get("descriptions"):
        desc = cve["descriptions"][0]["value"]
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    vendor, product = _extract_vendor_product(cve)
    return {
        "cve_id": cve.get("id"),
        "title": cve.get("sourceIdentifier"),
        "description": desc,
        "cvss_base": cvss,
        "cvss_vector": vector,
        "severity": severity,
        "published": published.split("T")[0] if published else None,
        "last_modified": last_modified.split("T")[0] if last_modified else None,
        "vendor": vendor,
        "product": product,
        "source_list": ["NVD"],
        "euvd_notes": None,
        "advisory_url": _extract_advisory_url(cve),
        "plain_summary": None,
        "safe_action": None,
        "integrity_notes": [],
        "conflict_flag": 0,
    }


def normalize_kev(row: Dict) -> Dict:
    cve_id = row.get("cveID")
    vendor = row.get("vendorProject")
    product = row.get("product")
    due_date = row.get("dueDate")
    return {
        "cve_id": cve_id,
        "kev": True,
        "vendor": vendor,
        "product": product,
        "due_date": due_date,
        "description": row.get("vulnerabilityName"),
    }


def merge_records(record: Dict, kev: Dict | None) -> Dict:
    if kev:
        record.setdefault("source_list", []).append("KEV")
        if not record.get("title"):
            record["title"] = kev.get("description")
        if kev.get("vendor") and record.get("vendor") and kev.get("vendor") != record.get("vendor"):
            record.setdefault("integrity_notes", []).append("vendor_conflict")
            record["conflict_flag"] = 1
        if kev.get("product") and record.get("product") and kev.get("product") != record.get("product"):
            record.setdefault("integrity_notes", []).append("product_conflict")
            record["conflict_flag"] = 1
        if not record.get("vendor") and kev.get("vendor"):
            record["vendor"] = kev.get("vendor")
        if not record.get("product") and kev.get("product"):
            record["product"] = kev.get("product")
        record.setdefault("integrity_notes", []).append("kev_enriched")
    record["source_list"] = sorted(set(record.get("source_list", [])))
    return record


def flag_keywords(text: str, keywords: set[str]) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in keywords)


def score_record(record: Dict, kev: Dict | None) -> Dict:
    description = record.get("description", "")
    bio_score = 0
    kev_flag = bool(kev)
    if kev_flag:
        bio_score += 3
    ics_flag = flag_keywords(description, ICS_KEYWORDS)
    if ics_flag:
        bio_score += 2
    medical_flag = flag_keywords(description, MEDICAL_KEYWORDS)
    if medical_flag:
        bio_score += 2
    cvss = record.get("cvss_base") or 0
    cvss_high_flag = cvss >= 8
    if cvss_high_flag:
        bio_score += 1
    recent_flag = False
    published = record.get("published")
    if published:
        pub_date = dt.datetime.fromisoformat(str(published))
        if (dt.datetime.utcnow() - pub_date).days <= 14:
            recent_flag = True
            bio_score += 1
    bio_keyword_flag = flag_keywords(description, BIO_KEYWORDS)
    if bio_keyword_flag:
        bio_score += 1
    categories: List[str] = []
    if kev_flag:
        categories.append("KEV")
    if ics_flag:
        categories.append("ICS")
    if medical_flag:
        categories.append("Medical")
    if bio_keyword_flag:
        categories.append("Bio")
    if record.get("severity"):
        categories.append(record["severity"].title())
    tags = {
        "cve_id": record["cve_id"],
        "kev_flag": int(kev_flag),
        "ics_flag": int(ics_flag),
        "medical_flag": int(medical_flag),
        "bio_keyword_flag": int(bio_keyword_flag),
        "recent_flag": int(recent_flag),
        "cvss_high_flag": int(cvss_high_flag),
        "bio_score": bio_score,
        "source_count": len(record.get("source_list", [])),
        "confidence_level": "high" if kev_flag or len(record.get("source_list", [])) >= 2 else "low",
        "conflict_flag": int(record.get("conflict_flag", 0)),
        "category_labels": categories,
        "notes": ",".join(record.get("integrity_notes", [])) or None,
    }
    return tags


def derive_summary(description: str) -> Optional[str]:
    if not description:
        return None
    summary = description.strip().replace("\n", " ")
    if ". " in summary:
        summary = summary.split(". ")[0] + "."
    return summary[:280]


def pick_safe_action(tags: Dict, record: Dict, kev: Dict | None) -> Optional[str]:
    if kev and kev.get("due_date"):
        return f"Follow CISA KEV guidance; remediate before {kev['due_date']}."
    if record.get("advisory_url"):
        return "Apply vendor guidance/patch per linked advisory."
    if tags.get("ics_flag"):
        return "Segment affected ICS assets and restrict network access until patched."
    if tags.get("medical_flag"):
        return "Coordinate with clinical engineering to apply vendor update with patient safety review."
    if tags.get("bio_keyword_flag"):
        return "Review lab controls and update firmware/software per vendor recommendations."
    if tags.get("cvss_high_flag"):
        return "Prioritize remediation alongside other critical vulnerabilities."
    return None


def run() -> None:
    lookback_days = int(os.environ.get("FETCH_LOOKBACK_DAYS", "7"))
    since = dt.datetime.utcnow() - dt.timedelta(days=lookback_days)
    logger.info("Fetching NVD items since %s", since.isoformat())
    nvd_items = fetch_nvd_items(since)
    kev_rows = {row["cveID"]: normalize_kev(row) for row in fetch_kev_items()}
    conn = queries.get_connection()
    queries.init_db(conn)
    loaded = 0
    for idx, item in enumerate(nvd_items, start=1):
        record = normalize_nvd(item)
        cve_id = record.get("cve_id")
        if not cve_id:
            logger.warning("Skipping item with no CVE ID: %s", item)
            continue
        kev_data = kev_rows.get(cve_id)
        merged = merge_records(record, kev_data)
        tags = score_record(merged, kev_data)
        summary = derive_summary(merged.get("description", ""))
        if summary:
            merged["plain_summary"] = summary
        action = pick_safe_action(tags, merged, kev_data)
        if action:
            merged["safe_action"] = action
        if merged.get("safe_action", "").lower().startswith("follow cisa kev guidance"):
            due_date = kev_data.get("due_date") if kev_data else None
            if due_date:
                try:
                    due = dt.datetime.fromisoformat(due_date).date()
                    if due < dt.datetime.utcnow().date():
                        merged["safe_action"] = merged["safe_action"].rstrip(".") + " (overdue)."
                except ValueError:
                    pass
        queries.upsert_vuln(conn, merged)
        queries.upsert_tag(conn, tags)
        if idx % 25 == 0:
            logger.info("Upserted %s vulnerabilities...", idx)
        loaded += 1
    logger.info("Loaded %s vulnerabilities", loaded)
    conn.close()


if __name__ == "__main__":
    run()
