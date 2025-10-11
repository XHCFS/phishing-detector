# Risk Scoring Implementation Summary

## Overview
Automated risk scoring has been integrated into the email processing pipeline. Risk scores are calculated in real-time when emails are received and URLs are extracted.

## Risk Scoring Logic

### For URLs in `enriched_threats` table

#### Non-Email Sources (External Threat Feeds)
- **Risk Score:** Always `100` (maximum risk)
- **Applied to:** URLs where `source_feed != 'email'`
- **Examples:** PhishTank, URLhaus, OpenPhish feeds

#### Email Sources
- **Risk Score:** Calculated using `scoring.py` criteria (0-100)
- **Applied to:** URLs where `source_feed = 'email'`
- **Components:**
  1. **Liveness (0-35 pts)** - HTTP status and online status
  2. **Recency (0-25 pts)** - Days since last seen
  3. **Domain Age (0-20 pts)** - Days since domain creation
  4. **TLD/Platform (0-10 pts)** - Suspicious TLDs (.zip, .click) and ephemeral platforms
  5. **Keywords (0-10 pts)** - Suspicious keywords (login, verify, bank, etc.)

### For Emails in `emails` table
- **Risk Score:** `MAX(risk_score)` of all linked URLs
- **Logic:** If any URL has risk_score=100, the email gets 100
- **Automatic:** Calculated after all URLs are processed

## Risk Levels

| Score Range | Risk Level | Indicator |
|-------------|------------|-----------|
| 85-100      | Critical   | 🚨        |
| 70-84       | High       | ⚠️        |
| 50-69       | Medium     | ⚡        |
| 0-49        | Low        | ✓         |

## When Scores Are Calculated

### Automatic Calculation Points:
1. **When email is received** → URLs extracted → Risk scores calculated
2. **When URL is enriched** → Risk score calculated immediately
3. **When URL is linked to email** → Email risk score updated to MAX

### Flow Diagram:
```
Email Received
    ↓
Extract URLs
    ↓
For each URL:
    ├─ Check if in threat feed (source != 'email')
    │  ├─ YES → Set URL risk_score = 100
    │  └─ Link to email
    │
    ├─ Check if already enriched (source = 'email')
    │  ├─ YES → Recalculate risk_score using scoring.py
    │  └─ Link to email
    │
    └─ New URL → Enrich → Calculate risk_score → Link to email
    ↓
Update Email risk_score = MAX(all linked URLs' risk_scores)
    ↓
Report final risk level
```

## Functions Added to `core.py`

### `calculate_and_set_url_risk_score(url_id: int)`
- Calculates and updates risk score for a URL
- Returns the calculated score
- Logic:
  - If `source_feed != 'email'`: score = 100
  - If `source_feed = 'email'`: score = calculated using `scoring.py`

### `update_email_risk_score(email_id: str, risk_score: int = None)`
- Updates email risk score
- If `risk_score=None`: automatically calculates as MAX of all linked URLs
- If `risk_score` provided: sets it directly

## Database Schema Updates

### `enriched_threats` table
- Already has `risk_score INTEGER DEFAULT 0` column
- Index: `idx_enriched_risk_score`

### `emails` table
- Already has `risk_score INTEGER DEFAULT 0` column
- Index: `idx_emails_risk_score`

## Example Scoring Scenarios

### Scenario 1: Email with PhishTank URL
```
Email contains: https://phishing-site.com/login
URL found in PhishTank feed → risk_score = 100
Email risk_score = 100 (Critical) 🚨
```

### Scenario 2: Email with New Suspicious URL
```
Email contains: https://secure-login.zip/verify
URL not in any feed → Enrich and calculate:
  - Liveness: 35 (HTTP 200)
  - Recency: 25 (seen today)
  - Domain Age: 20 (created 2 days ago)
  - TLD: 10 (.zip is high-risk)
  - Keywords: 10 (contains "login" and "verify")
  Total: 100
Email risk_score = 100 (Critical) 🚨
```

### Scenario 3: Email with Legitimate URL
```
Email contains: https://github.com/user/repo
URL not in threat feeds → Enrich and calculate:
  - Liveness: 35 (HTTP 200)
  - Recency: 5 (not recently reported)
  - Domain Age: 5 (old domain, created 2008)
  - TLD: 5 (.com, not ephemeral)
  - Keywords: 0 (no suspicious keywords)
  Total: 50
Email risk_score = 50 (Medium) ⚡
```

### Scenario 4: Email with Multiple URLs
```
Email contains:
  - https://google.com → score: 45
  - https://github.com → score: 50
  - https://suspicious.click/login → score: 95
Email risk_score = 95 (Critical) 🚨  (MAX of all URLs)
```

## Performance

- **Async Processing:** All URLs enriched in parallel
- **Smart Caching:** Existing URLs not re-enriched
- **Real-time Scoring:** Scores calculated during enrichment
- **No Manual Updates:** Fully automated

## Testing Commands

```bash
# Process emails and see risk scores
python -m app.detector.core --fetch 10

# Enrich existing emails
python -m app.detector.core --enrich-all

# Check risk scores in database
sqlite3 app/database/threat_feeds.db \
  "SELECT sender, subject, risk_score FROM emails ORDER BY risk_score DESC LIMIT 10"
```

## Output Examples

```
Enriching new URL: https://secure-login.zip/verify
✓ Enriched and linked URL: https://secure-login.zip/verify (risk score: 100)
🚨 Email 12345xyz marked as CRITICAL RISK (score: 100)
```

```
⚠️  High risk: URL https://phishing.com/login found in threat feed!
🚨 Email 67890abc marked as CRITICAL RISK (score: 100)
```

```
✓ Enriched and linked URL: https://example.com/page (risk score: 42)
✓ Email 11111def marked as LOW RISK (score: 42)
```

## Benefits

✅ **Automated** - No manual scoring needed
✅ **Real-time** - Scores calculated as emails arrive
✅ **Accurate** - Uses multiple threat feeds + heuristics
✅ **Fast** - Async processing for speed
✅ **Transparent** - Clear risk levels and indicators
✅ **Extensible** - Easy to adjust scoring criteria in `scoring.py`

