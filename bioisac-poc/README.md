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

