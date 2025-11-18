# Bio-ISAC Vulnerability Triage POC

Slack-based triage assistant that ingests NVD, CISA KEV, and EUVD data, scores bio relevance, and surfaces prioritized intel to Bio-ISAC via slash commands and daily digests.

## Getting Started

1. **Enter project directory and set up virtualenv:**
   ```bash
   cd bioisac-poc
   python3 -m venv .venv  # macOS/Linux (or: python -m venv .venv on Windows)
   source .venv/bin/activate  # macOS/Linux (or: .\.venv\Scripts\Activate on Windows)
   ```
   **Note:** `.venv` is git-ignored and must be created on each machine. You only need to create it once per machine.

2. **Install dependencies** (only needed if packages are missing):
   ```bash
   pip install -r requirements.txt
   ```

3. **Create `.env` file** (first time only — file persists after creation):
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and replace placeholder values with your actual credentials:
   - Slack: `SLACK_BOT_TOKEN`, `SLACK_APP_LEVEL_TOKEN`, `ALLOWED_USERS`, `ALLOWED_CHANNELS`, `DIGEST_CHANNEL`
   - Database: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`, `DB_PORT`
   - Optional: `NVD_API_KEY`, `FETCH_LOOKBACK_DAYS`, `DIGEST_LOOKBACK_HOURS`, `LOG_LEVEL`
   
   **Note:** `.env` is git-ignored and won't be pushed to GitHub. Each team member creates their own `.env` file.
   
   **ETL Configuration:**
   - `FETCH_LOOKBACK_DAYS` (default: 7) — How many days back to fetch modified CVEs
     - **Initial setup:** Set to `30-90` days to build a comprehensive baseline dataset
     - **Daily runs:** `7` days (default) is sufficient for regular updates
     - **Weekly runs:** `14-30` days to catch updates you might have missed

4. **Initialize database schema** (first time only):
   ```bash
   python -m src.db_test
   ```

5. **Pull initial vulnerability data** (first time setup):
   ```bash
   python -m src.etl.etl_starter
   ```
   **Important:** 
   - This fetches CVEs modified within the `FETCH_LOOKBACK_DAYS` window (default 7 days)
   - For initial setup, set `FETCH_LOOKBACK_DAYS=30` in `.env` to build a comprehensive baseline
   - Data persists in the database — you don't need to reload everything each time you open the project
   - The ETL uses upsert logic, so it updates existing CVEs and adds new ones without duplicates

6. **Start the bot:**
   ```bash
   python -m src.bot.bot
   ```
   Keep the process running to use `/bioisac` commands in Slack. Press `Ctrl+C` to stop gracefully.

---

## Day-to-Day Workflow

### Data Management

**When to Run ETL:**
- **First time:** Run once to populate the database (recommend `FETCH_LOOKBACK_DAYS=30` for initial setup)
- **Daily/Regular:** Run to catch new CVEs and updates to existing ones (default 7-day lookback is fine)
- **After gaps:** If you haven't run ETL in a while, run it to catch up on missed updates

**ETL Behavior:**
- The ETL is **incremental** — it updates existing CVEs and adds new ones
- Data **persists** in your database between sessions — no need to reload everything each time
- Uses `ON DUPLICATE KEY UPDATE`, so running ETL multiple times is safe and efficient
- Fetches CVEs modified within the lookback window (not just new ones), so you catch updates to existing vulnerabilities

**Refresh data:**
```bash
python -m src.etl.etl_starter
```
Pulls latest NVD + KEV entries, recalculates bio-relevance scores, and updates the database.

### Other Common Tasks

- **Send digest** – `python -m src.bot.daily_digest` (post top vulnerabilities to configured channel)
- **Health check** – `python -m src.qa.qa_smoke` (verify env vars, DB connection, Slack auth)

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
Retrieve the top N vulnerabilities ranked by bio-relevance scoring algorithm. Default limit is 10, with support for requesting up to 100 vulnerabilities.

**Usage:**
```
/bioisac top          # Returns top 10 vulnerabilities (default)
/bioisac top 20       # Returns top 20 vulnerabilities
/bioisac top 50       # Returns top 50 vulnerabilities
```
**Parameters:**
- `n` (optional): Number of results (default: 10, max: 100)

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
- 🔴 CRITICAL - CVSS 9.0-10.0 (Red)
- 🟠 HIGH - CVSS 7.0-8.9 (Orange)
- 🟡 MEDIUM - CVSS 4.0-6.9 (Yellow)
- 🟢 LOW - CVSS 0.1-3.9 (Green)

**Vulnerability Cards Include:**
- CVE identifier with severity badge
- Priority indicators (if applicable)
- CVSS score and affected vendor/product
- Plain-language summary
- Recommended action
- Advisory links
- Source intelligence feeds
- Bio-relevance score (0-10)

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
- Empty values = no restrictions (anyone can use the bot)
- Populated values = whitelist enforcement (only listed users/channels can access)
- Denied requests receive an "Access Denied" message with instructions

**How Users Can Request Access:**

1. **User tries to use the bot** → Receives "Access Denied" message
2. **User contacts administrator** → Provides their Slack user ID
3. **Administrator adds user ID** → Updates `.env` file with user's Slack ID
4. **Administrator restarts bot** → New permissions take effect

**Finding Slack User IDs:**

- **Method 1:** Right-click user in Slack → "View profile" → User ID is in the profile URL
- **Method 2:** Ask the bot administrator to check (they can see user IDs in bot logs)
- **Method 3:** Use Slack API or developer tools (for technical users)

**Administrator Steps to Add a User:**

1. Get the user's Slack user ID (format: `U01234ABC`)
2. Edit `.env` file: `ALLOWED_USERS=U123ABC,U456DEF,U789GHI` (comma-separated, no spaces)
3. Restart the bot: `python -m src.bot.bot`
4. User can now access the bot

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
