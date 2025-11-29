# TA Grading Guide - Bio-ISAC Vulnerability Intelligence Platform

This document provides suggestions on what to look at in this project when it comes to grading.


## What to Test

### 1. Slack Bot Commands

Test each command in the Slack channel:

**Basic Commands:**
- `/bioisac help` - Should display comprehensive help menu
- `/bioisac top` - Should return top 10 vulnerabilities
- `/bioisac top 20` - Should return top 20 vulnerabilities
- `/bioisac stats` - Should display database statistics

**Search and Detail:**
- `/bioisac search [keyword]` - Test with a vendor name or CVE ID
- `/bioisac detail CVE-2024-XXXX` - Test with a real CVE from the database
- `/bioisac recent` - Should show recent vulnerabilities (last 24 hours)
- `/bioisac recent 48` - Should show last 48 hours

**Digest Setup:**
- `/bioisac digest-setup` - Should show help for digest customization
- `/bioisac digest-setup show` - Should show current preferences (if any set)
- `/bioisac digest-setup set time:9:00 AM` - Should set digest time to 9 AM
- `/bioisac digest-setup set medical cvss-min:7.0 time:14:00` - Should set filters and time
- `/bioisac digest-setup show` - Verify preferences were saved

### 2. Response Quality

Check that responses include:
- Professional formatting
- Color-coded severity badges (🔴 Critical, 🟠 High, etc.)
- Priority indicators (KEV, MEDICAL, ICS, BIO-RELEVANT)
- Structured information (CVE ID, CVSS, vendor/product)
- Advisory links
- Bio-relevance scores

### 3. Error Handling

Test error scenarios:
- Invalid commands (should show helpful error message)
- Invalid CVE format (should show format requirements)
- Out-of-range parameters (should show valid ranges)
- Search with no results (should show helpful message)

### 4. Daily Digest

**Note:** Daily digest runs automatically. To test manually:
- Ask student to run: `heroku run "python -m src.bot.daily_digest" --app mis321-gp3-group15`
- Or wait for scheduled time (check Heroku Scheduler configuration)

Verify:
- Digest posts to configured channel
- Includes executive summary
- Shows high-priority vulnerabilities
- Professional formatting

### 5. User Personalization

Test digest-setup features:
- Set time preference (must be top of hour, e.g., 9:00 AM)
- Set filter preferences (medical, ics, bio, kev, cvss-min, bio-min, limit)
- Verify preferences are saved
- Check that time validation works (should reject 9:05 AM)

---

## Code Review Checklist Suggesstion

### Architecture
- [ ] Clean separation of concerns (ETL, bot, database)
- [ ] Modular code structure
- [ ] Reusable functions and components
- [ ] Proper error handling

### Database Design
- [ ] Well-designed schema (vulns, tags, digest_preferences tables)
- [ ] Proper relationships and constraints
- [ ] Efficient queries
- [ ] User preference storage

### Bot Implementation
- [ ] All commands implemented
- [ ] Professional response formatting
- [ ] Input validation
- [ ] Error messages are helpful
- [ ] Authorization working correctly

### ETL Process
- [ ] Data collection from multiple sources
- [ ] Data normalization
- [ ] Bio-relevance scoring algorithm
- [ ] Incremental updates (not re-processing everything)
- [ ] Error handling for API failures

### New Features (Digest Time Customization)
- [ ] Time parsing (12-hour and 24-hour formats)
- [ ] Validation (top of hour requirement)
- [ ] Database schema includes digest_time column
- [ ] Daily digest checks time preferences
- [ ] Help text updated with time option

### Code Quality
- [ ] Consistent coding style
- [ ] Meaningful variable names
- [ ] Comments where needed
- [ ] No obvious bugs or security issues

---

### Documentation Quality
- [ ] Clear and comprehensive
- [ ] Non-technical readers can understand
- [ ] Includes examples
- [ ] Explains architecture and design decisions

---

## Deployment Verification

### Heroku Configuration
- [ ] Bot running 24/7 (check Heroku dashboard or ask student)
- [ ] ETL scheduled to run daily
- [ ] Daily digest scheduled (hourly for time preferences)
- [ ] Environment variables properly configured
- [ ] Database initialized and populated

### System Health
- [ ] Commands respond quickly (< 2 seconds)
- [ ] No error messages in logs (check if possible)
- [ ] Database contains vulnerability data
- [ ] All integrations working (Slack, APIs)

---

## Common Issues to Check

1. **Bot Not Responding:** Check if worker dyno is scaled up
2. **Empty Results:** Database may need initial ETL run
3. **Permission Errors:** Verify Slack ID is in ALLOWED_USERS
4. **Time Preferences Not Working:** Verify Heroku Scheduler runs hourly
5. **Formatting Issues:** Check if responses are properly formatted

---

## Notes

- The system is production-ready and actively running
- All features are deployed and functional
- TA can test everything via Slack - no Heroku access needed
- Database contains real vulnerability data from NVD, CISA KEV, EUVD
- Daily digest runs automatically (can be tested manually if needed)
