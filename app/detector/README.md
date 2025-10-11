# Phishing Detector Module

Email analysis system that fetches emails from Gmail, extracts URLs, and calculates risk scores using threat intelligence.

## Quick Start

### 1. Setup Gmail OAuth

```bash
# Place credentials.json in this directory
cp ~/Downloads/credentials.json app/detector/credentials.json

# Authenticate (opens browser for OAuth)
python -m app.detector.core --authenticate
```

### 2. Fetch and Analyze Emails

```bash
# Bootstrap: Setup + Fetch + Analyze (all-in-one)
python -m app.detector.core --bootstrap --max-fetch 25
```

That's it! Emails are analyzed and risk scores calculated automatically.

---

## Features

- **Gmail Integration** - OAuth 2.0 authentication with auto-refresh
- **URL Extraction** - Regex-based extraction from plain text and HTML
- **Async Enrichment** - Parallel URL processing for speed
- **Risk Scoring** - 0-100 scale based on 5 factors
- **Threat Detection** - Automatic matching with PhishTank, URLhaus, OpenPhish
- **REST API** - FastAPI endpoints for programmatic access

---

## System Architecture

```
Gmail API → Fetch Emails → Extract URLs → Process URLs
                                            ├─ Check threat feeds → risk=100
                                            ├─ Check existing → recalculate
                                            └─ New → Enrich → Score → Store
                                                      ↓
Email risk_score = MAX(all URL scores)
```

---

## Command Reference

### Setup

```bash
# Create database tables
python -m app.detector.core --setup-db

# Authenticate with Gmail (required first time)
python -m app.detector.core --authenticate
```

### Fetch Emails

```bash
# Fetch 25 emails (default)
python -m app.detector.core --fetch

# Fetch 100 emails
python -m app.detector.core --fetch 100

# Custom credentials file
python -m app.detector.core --fetch --credentials /path/to/credentials.json
```

### Enrich URLs

```bash
# Enrich specific email
python -m app.detector.core --enrich-email msg123abc

# Enrich all emails in database
python -m app.detector.core --enrich-all
```

### Bootstrap (All-in-One)

```bash
# Setup DB + Fetch 50 emails + Enrich
python -m app.detector.core --bootstrap --max-fetch 50
```

### Testing

```bash
# Insert sample email for testing
python -m app.detector.core --seed-sample
```

---

## Risk Scoring

### Components (0-100 scale)

| Component | Points | Description |
|-----------|--------|-------------|
| **Liveness** | 0-35 | HTTP status and online status |
| **Recency** | 0-25 | Days since last seen in threat feeds |
| **Domain Age** | 0-20 | Days since domain creation |
| **TLD/Platform** | 0-10 | Suspicious TLDs (.zip, .click) and ephemeral platforms |
| **Keywords** | 0-10 | Suspicious keywords (login, verify, bank) |

### Risk Levels

| Score | Level | Indicator |
|-------|-------|-----------|
| 85-100 | Critical | 🚨 |
| 70-84 | High | ⚠️ |
| 50-69 | Medium | ⚡ |
| 0-49 | Low | ✓ |

### Email Risk Score

**Email risk_score = MAX(all linked URL risk_scores)**

If any URL in an email has risk_score=100, the email gets risk_score=100.

---

## REST API

**Base URL:** `http://localhost:8000/detector`

### `GET /check`

Analyze a specific email by ID.

**Request:**
```http
GET /detector/check?email_id=msg123
```

**Response:**
```json
{
  "email_id": "msg123",
  "result": "Scanned msg123: enriched 3 URLs"
}
```

---

## Configuration

### Gmail OAuth Setup

**1. Create Google Cloud Project**
```
1. Go to https://console.cloud.google.com/
2. Create project: "Phishing Detector"
3. Enable Gmail API
4. Create OAuth 2.0 credentials (Desktop app)
5. Download credentials.json
```

**2. Configure OAuth Consent Screen**
```
1. App name: "Phishing Detector"
2. Scopes: "Gmail Read-only"
   https://www.googleapis.com/auth/gmail.readonly
3. Test users: Add your Gmail address
```

**3. Place credentials.json**
```bash
cp ~/Downloads/credentials.json app/detector/credentials.json
```

**4. Authenticate**
```bash
python -m app.detector.core --authenticate
# Browser opens → Select Gmail → Allow → Done
# token.json created automatically
```

### OAuth Files

| File | Purpose | Source |
|------|---------|--------|
| `credentials.json` | OAuth client secrets | Google Cloud Console |
| `token.json` | User access token | Generated during first auth |

**Security:** Add both to `.gitignore` (already done)

---

## File Structure

```
app/detector/
├── README.md                    # This file
├── core.py                      # Main email fetcher and URL processor (670 lines)
├── api.py                       # FastAPI endpoints (10 lines)
├── scoring.py                   # Risk scoring algorithm (200 lines)
├── credentials.json             # OAuth client secrets (place here)
├── credentials.json.example     # Example template
├── token.json                   # Generated OAuth token (auto-created)
└── Documentation/
    └── DETECTOR_GUIDE.md        # Complete technical documentation (680 lines)
```

---

## Usage Examples

### Python API

#### Fetch and Process
```python
from app.detector.core import (
    fetch_and_store_recent_emails,
    enrich_urls_for_email
)

# Fetch 10 emails
email_ids = fetch_and_store_recent_emails(max_results=10)

# Process each email
for email_id in email_ids:
    num_urls = enrich_urls_for_email(email_id)
    print(f"Processed {num_urls} URLs in {email_id}")
```

#### Check Risk Scores
```python
import sqlite3

conn = sqlite3.connect('app/database/threat_feeds.db')
cur = conn.cursor()

# Get high-risk emails
cur.execute("""
    SELECT sender, subject, risk_score
    FROM emails
    WHERE risk_score >= 70
    ORDER BY risk_score DESC
""")

for sender, subject, score in cur.fetchall():
    print(f"{score}/100 | {sender} | {subject}")
```

### REST API

#### curl
```bash
curl "http://localhost:8000/detector/check?email_id=msg123"
```

#### Python requests
```python
import requests

response = requests.get(
    'http://localhost:8000/detector/check',
    params={'email_id': 'msg123'}
)
print(response.json())
```

---

## Troubleshooting

### Gmail OAuth Issues

**"credentials.json not found"**
```bash
# Ensure file exists
ls app/detector/credentials.json

# If missing, download from Google Cloud Console
```

**"OAuth flow failed"**
```bash
# Delete old token and re-authenticate
rm app/detector/token.json
python -m app.detector.core --authenticate
```

**"Port 8080 in use"**
```bash
# Check what's using port
lsof -i :8080

# Manual flow automatically triggers if port unavailable
```

### Processing Issues

**"No URLs found"**
```bash
# Check email body content
sqlite3 app/database/threat_feeds.db \
  "SELECT body_plain FROM emails WHERE id = 'msg123'"
```

**"Risk scores all 0"**
```bash
# Run enrichment
python -m app.detector.core --enrich-all
```

**"Too slow"**
```bash
# Reduce URLs per email (edit core.py)
# Change max_per_email = 20 (from 50)

# Or increase parallel workers
# Change max_workers = 20 (from 10)
```

---

## Documentation

- **[DETECTOR_GUIDE.md](Documentation/DETECTOR_GUIDE.md)** - Complete technical documentation (680 lines)
  - Detailed architecture and data flow
  - Gmail OAuth setup guide
  - URL extraction and normalization
  - Risk scoring algorithm deep-dive
  - Python API reference
  - Comprehensive troubleshooting

---

## Dependencies

```bash
# Required
pip install google-auth google-auth-oauthlib google-api-python-client

# Optional (for faster enrichment)
pip install aiohttp
```

See `requirements.txt` for full list.

---

## Summary

**Workflow:**
1. Authenticate with Gmail (once)
2. Fetch emails
3. Extract URLs from email bodies
4. Process URLs (check threat feeds → enrich → score)
5. Update email risk scores
6. Access via API or database

**Performance:**
- Async URL processing (10+ URLs in parallel)
- Smart caching (no re-enrichment)
- Typical: ~5-10 seconds per email

**Best Practices:**
- Run `--authenticate` before starting web app
- Use `--bootstrap` for initial setup
- Monitor high-risk emails regularly
- Update threat feeds daily

---

Ready to detect phishing emails!
