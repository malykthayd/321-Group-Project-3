# Bio-ISAC Vulnerability Triage POC

Slack-based triage assistant that ingests NVD, CISA KEV, and EUVD data, scores bio relevance, and surfaces prioritized intel to Bio-ISAC via slash commands and daily digests.

## First-Time Setup

1. **Clone + enter project**  
   ```bash
   cd bioisac-poc
   ```
2. **Create virtualenv (Python 3.11 recommended)**  
   - macOS/Linux:  
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - Windows (PowerShell):  
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate
     ```
3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```
4. **Copy env template and fill values**  
   ```bash
   cp .env.example .env
   ```
   Required keys:
   - Slack: `SLACK_BOT_TOKEN`, `SLACK_APP_LEVEL_TOKEN`, `ALLOWED_USERS`, `ALLOWED_CHANNELS`, `DIGEST_CHANNEL`
   - Database (JawsDB): `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `DB_PORT`
   - Optional: `NVD_API_KEY`, `FETCH_LOOKBACK_DAYS`, `DIGEST_LOOKBACK_HOURS`, `LOG_LEVEL`
5. **Prime the database schema**  
   ```bash
   python -m src.db_test
   ```
6. **Pull fresh vulnerabilities (ETL)**  
   ```bash
   python -m src.etl.etl_starter
   ```
   - Default lookback is 1 day; adjust `FETCH_LOOKBACK_DAYS` before running if you want a larger window.
7. **Run the Slack bot locally**  
   ```bash
   python -m src.bot.bot
   ```
   - In Slack, test `/bioisac top 5` and `/bioisac search mitel`.  
   - Leave the process running while you exercise commands (`Ctrl+C` to stop).
8. **Optional manual digest**  
   ```bash
   python -m src.bot.daily_digest
   ```
   Posts the top items to the channel in `DIGEST_CHANNEL`.

## Day-to-Day Workflow

- **Refresh data** – rerun `python -m src.etl.etl_starter` to pull the latest NVD + KEV entries and recalc scores.
- **Operate bot** – start `python -m src.bot.bot` whenever you want to use `/bioisac top [n]` or `/bioisac search <keyword>`.
- **Send digest** – `python -m src.bot.daily_digest` posts the top list to the configured channel on demand.
- **Health check** – `python -m src.qa.qa_smoke` confirms env vars, DB connection, and Slack auth.
- **Change lookback window** – edit `.env` (`FETCH_LOOKBACK_DAYS`, `DIGEST_LOOKBACK_HOURS`), then rerun ETL/digest.

## What Lives Where (cheat sheet)

- `src/db_test.py` – applies schema + prints row count (good first sanity check).
- `src/etl/etl_starter.py` – ETL entrypoint (fetch NVD + CISA KEV, score, upsert, add overdue notes).
- `src/etl/queries.py` – reusable DB helpers used by both ETL and bot.
- `src/bot/bot.py` – Slack Bolt worker handling `/bioisac top` + `/bioisac search`.
- `src/bot/daily_digest.py` – posts the formatted digest (same cards as the top command).
- `src/qa/qa_smoke.py` – quick smoke script to verify env, DB, Slack setup.
- `logs/etl.log` – rolling log with ingestion status, conflicts, and errors.

## Project Structure

```
bioisac-poc/
  src/
    etl/
    bot/
    qa/
```

- `src/schema.sql` – defines `vulns` (summary, safe-action, advisory fields) and `tags` (scoring + category labels).
- `src/etl` – ingest, normalize, score, and upsert vulnerability data.
- `src/bot` – Slack Bolt app, slash commands, daily digest poster.
- `src/qa/qa_smoke.py` – connectivity smoke test for DB + Slack.
- EUVD enrichment hooks are scaffolded but not yet fetching data—extend `src/etl/etl_starter.py` when you’re ready.

## Heroku

- `Procfile` defines `worker` dyno for the Slack bot.
- Use Heroku Scheduler to run `python -m src.etl.etl_starter` daily.
- Scheduler can also call `python -m src.bot.daily_digest` for ad-hoc digests if you prefer server-side triggers.
- Deployment checklist:
  1. Push repo to Heroku (`git push heroku main` or GitHub integration).
  2. Configure all `.env` variables as Heroku config vars.
  3. Scale the `worker` dyno (`heroku ps:scale worker=1`).
  4. Add two Scheduler jobs (daily ETL, daily digest) after confirming the worker runs and Slack commands succeed.

## Logging

ETL writes details to `logs/etl.log` (created automatically). Review regularly for conflicts, missing data, and ingestion errors. Daily digests honor `DIGEST_LOOKBACK_HOURS` (default 24) so analysts only see fresh or recently updated CVEs.

## Slack Integration

### Bio-ISAC Vulnerability Intelligence Platform

The Bio-ISAC Slack bot provides an enterprise-grade interface for querying vulnerability intelligence directly within Slack. Designed for security teams, analysts, and leadership, it delivers high-signal threat intelligence without disrupting workflow.

All responses follow professional formatting standards with severity classification, priority indicators, and actionable recommendations.

---

### Slack Bot Command Reference

#### `/bioisac help`
Display comprehensive command documentation including usage patterns, examples, priority indicators, and severity classifications.

**Usage:**
```
/bioisac help
```
**Use Cases:** Onboarding new team members, quick reference, understanding priority indicators and severity levels

---

#### `/bioisac top [n]`
Retrieve the top N vulnerabilities ranked by bio-relevance scoring algorithm. Default limit is 5, with automatic pagination at 10 results to maintain message readability.

**Usage:**
```
/bioisac top          # Returns top 5 vulnerabilities
/bioisac top 10       # Returns top 10 vulnerabilities
```
**Parameters:**
- `n` (optional): Number of results (default: 5, max display: 10)

**Use Cases:** Daily triage, priority assessment, executive briefings

---

#### `/bioisac search <keyword>`
Full-text search across CVE IDs, vendors, products, and vulnerability titles. Results are ranked by bio-relevance with automatic pagination at 10 matches.

**Usage:**
```
/bioisac search illumina          # Search for Illumina products
/bioisac search CVE-2024-1234     # Search specific CVE
/bioisac search medical device    # Broad keyword search
```
**Parameters:**
- `keyword` (required): Search term for vendor, product, CVE ID, or title

**Use Cases:** Vendor-specific investigations, product research, CVE lookup

---

#### `/bioisac recent [hours]`
Display vulnerabilities discovered or updated within a specified timeframe. Default is 24 hours with a valid range of 1-168 hours (7 days).

**Usage:**
```
/bioisac recent           # Last 24 hours (default)
/bioisac recent 48        # Last 48 hours
/bioisac recent 168       # Last 7 days
```
**Parameters:**
- `hours` (optional): Timeframe in hours (range: 1-168, default: 24)

**Validation:** Non-integer values or out-of-range numbers return professional error messages with examples

**Use Cases:** SOC operations, incident response, change management tracking

---

#### `/bioisac stats`
Generate comprehensive vulnerability statistics including database metrics, severity distribution, and priority classification counts.

**Usage:**
```
/bioisac stats
```
**Metrics Provided:**
- Total vulnerabilities in database
- Recent activity (24-hour window)
- Severity distribution (CRITICAL/HIGH/MEDIUM/LOW)
- Priority classifications (KEV, Medical, ICS, Bio-relevant)

**Use Cases:** Management reporting, metrics dashboards, trend analysis

---

#### `/bioisac detail <CVE-ID>`
Retrieve detailed intelligence report for a specific CVE identifier. Supports multiple input formats with automatic normalization.

**Usage:**
```
/bioisac detail CVE-2024-1234     # Standard format
/bioisac detail cve-2024-1234     # Lowercase accepted
/bioisac detail 2024-1234         # Auto-prefixes CVE-
```
**Parameters:**
- `CVE-ID` (required): CVE identifier in any standard format

**Normalization:** Handles case variations, spacing, and missing prefixes automatically

**Use Cases:** Deep-dive analysis, patch validation, risk assessment, incident investigation

---

### Response Formatting

All vulnerability responses include:

**Priority Indicators:**
- `KEV` - CISA Known Exploited Vulnerability
- `MEDICAL` - Medical device related
- `ICS` - Industrial Control System
- `BIO-RELEVANT` - Bio-industry keyword match

**Severity Classification:**
- ▪️ CRITICAL - CVSS 9.0-10.0
- ▪️ HIGH - CVSS 7.0-8.9
- ▪️ MEDIUM - CVSS 4.0-6.9
- ▪️ LOW - CVSS 0.1-3.9

**Vulnerability Cards Include:**
- CVE identifier with severity badge
- Priority indicators (if applicable)
- CVSS score and affected vendor/product
- Plain-language summary
- Recommended action
- Advisory links
- Source intelligence feeds
- Bio-relevance score (0-100)

**Pagination:**
List commands automatically truncate at 10 results with clear indication of total matches and suggestions for query refinement.

---

### Daily Digest

The automated Daily Security Digest provides scheduled vulnerability intelligence summaries to designated Slack channels.

#### Features

- **Executive Summary:** High-level overview of monitoring period and priority items
- **Smart Content:** Shows high-priority vulnerabilities from the last N hours, or top vulnerabilities if none recent
- **Professional Format:** Consistent with interactive command responses
- **Actionable Intelligence:** Includes recommended response protocol and next steps
- **Statistics:** Monitoring period metrics, priority counts, KEV tracking

#### Configuration

**Required Environment Variables:**
```bash
DIGEST_CHANNEL=C01234ABCDE          # Slack channel ID for digest posts
DIGEST_LOOKBACK_HOURS=24            # Timeframe for recent vulnerabilities (default: 24)
```

**Manual Execution:**
```bash
python -m src.bot.daily_digest
```

**Automated Scheduling (Heroku):**
1. Navigate to Heroku Scheduler add-on
2. Add new job: `python -m src.bot.daily_digest`
3. Set frequency (recommended: daily at 8:00 AM local time)
4. Ensure worker dyno is running

**Digest Content:**

*When High-Priority Items Exist:*
- Executive summary with counts
- Up to 10 vulnerability cards (same format as commands)
- Recommended response protocol
- Available analysis tools reference
- Generation timestamp

*When No High-Priority Items:*
- "Good news" summary
- Monitoring statistics
- KEV tracking
- Guidance for detailed analysis

#### Use Cases
- Daily team briefings
- Executive reporting
- SOC handoff documentation
- Compliance audit trails

---

### Permissions & Authorization

Access control is managed via environment variables:

```bash
ALLOWED_USERS=U01234ABC,U56789DEF    # Comma-separated Slack user IDs
ALLOWED_CHANNELS=C01234ABC,C56789DEF  # Comma-separated Slack channel IDs
```

**Authorization Behavior:**
- Empty values = no restrictions
- Populated values = whitelist enforcement
- Denied requests receive professional "Access Denied" message with administrator contact guidance

---

### Error Handling & Validation

All commands include professional error handling:

**Input Validation:**
- Parameter type checking
- Range validation with clear limits
- Format normalization (e.g., CVE ID variations)

**No Results Scenarios:**
- Consistent "Query Result: No matching vulnerabilities found" format
- Context-specific suggestions
- Guidance for alternative commands

**Error Messages:**
- Professional tone without casual language
- Clear next steps
- Example usage patterns

**Example Error Response:**
```
*Invalid Parameter:* Hours value `200` is out of range

*Valid Range:* 1-168 hours (1 hour to 7 days)

_Example:_ `/bioisac recent 48`
```

---

### Best Practices

**For Analysts:**
- Start your day with `/bioisac recent` to catch new threats
- Use `/bioisac search` for vendor-specific investigations
- Leverage `/bioisac detail` for deep-dive analysis before escalation

**For Management:**
- Review `/bioisac stats` for metrics and reporting
- Monitor daily digest for strategic oversight
- Use `/bioisac top` for executive briefings

**For SOC Teams:**
- Configure alerts to post `/bioisac recent` output to incident channels
- Document `/bioisac detail` outputs in incident tickets
- Track KEV indicators via daily digest

---
