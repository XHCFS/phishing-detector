# Phishing Detector Module - Complete Technical Guide

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Gmail Integration](#gmail-integration)
5. [URL Extraction and Processing](#url-extraction-and-processing)
6. [Risk Scoring System](#risk-scoring-system)
7. [API Endpoints](#api-endpoints)
8. [Usage Examples](#usage-examples)
9. [Configuration](#configuration)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The **Detector Module** is responsible for:
- Fetching emails from Gmail using OAuth 2.0 authentication
- Extracting URLs from email content (plain text and HTML)
- Enriching URLs with threat intelligence data
- Calculating risk scores for URLs and emails
- Linking emails to known threats in the database
- Providing REST API endpoints for email analysis

**Key Features:**
- ✅ Gmail API integration with OAuth 2.0
- ✅ Asynchronous URL enrichment (parallel processing)
- ✅ Automatic risk scoring using multi-factor algorithm
- ✅ Integration with threat intelligence feeds
- ✅ URL normalization and deduplication
- ✅ REST API for programmatic access

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DETECTOR MODULE                           │
└─────────────────────────────────────────────────────────────┘

    ┌────────────┐
    │  Gmail API │ ← OAuth 2.0 Authentication
    └──────┬─────┘
           │
           ▼
    ┌────────────────────┐
    │    core.py         │
    │  Email Fetcher     │ ← fetch_and_store_recent_emails()
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  Email Storage     │
    │  (emails table)    │ ← save_email_to_db()
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  URL Extractor     │ ← extract_urls_from_text()
    │  (Regex-based)     │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────────────────────────┐
    │   URL Processing Logic (core.py)       │
    ├────────────────────────────────────────┤
    │  1. Check threat feeds (source != email)|
    │     → If found: risk_score = 100       │
    │  2. Check existing URLs (source = email)|
    │     → If found: recalculate score      │
    │  3. New URLs: Enrich → Calculate score │
    └────────┬───────────────────────────────┘
             │
             ├──→ [Enrichment Module]
             │    ↓
             │   enrich.py (async)
             │    ↓
             │   DNS, WHOIS, GeoIP, SSL, HTTP
             │    ↓
             ▼
    ┌────────────────────┐
    │   scoring.py       │ ← calculate_risk_score()
    │  Risk Calculator   │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ enriched_threats   │
    │ (with risk_score)  │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ email_urls         │ ← link_email_to_url()
    │ (junction table)   │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  emails table      │
    │ (risk_score = MAX) │ ← update_email_risk_score()
    └────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │   API Response     │
    │   (api.py)         │ ← FastAPI endpoints
    └────────────────────┘
```

---

## Core Components

### 1. `core.py` (670 lines)

**Purpose:** Main orchestrator for email fetching, URL extraction, and threat detection

**Key Functions:**

#### Email Retrieval

##### `get_gmail_service(credentials_path: Optional[str] = None)`
Authenticates with Gmail API using OAuth 2.0.

**Flow:**
1. Checks for existing `token.json` (cached credentials)
2. If token exists and valid → reuse
3. If token expired → refresh using refresh token
4. If no token → initiate OAuth flow
   - Attempts local server method (port 8080)
   - Falls back to manual code entry if server fails
5. Saves token for future use

**Returns:** Authenticated Gmail service instance

**Errors:**
- `FileNotFoundError`: If `credentials.json` missing
- `RuntimeError`: If OAuth flow fails

##### `fetch_and_store_recent_emails(max_results: int = 25, credentials_path: Optional[str] = None)`
Fetches recent emails from Gmail and stores them in the database.

**Parameters:**
- `max_results`: Number of emails to fetch (default: 25)
- `credentials_path`: Path to OAuth credentials file

**Process:**
1. Authenticates with Gmail API
2. Retrieves message list
3. For each message:
   - Fetches full message data
   - Extracts headers (From, Subject, Date)
   - Decodes MIME-encoded headers
   - Extracts plain text and HTML bodies
   - Saves to `emails` table with `risk_score=0`

**Returns:** List of stored email IDs

#### URL Extraction and Processing

##### `extract_urls_from_text(text: str) -> List[str]`
Extracts URLs from text using regex.

**Regex Pattern:**
```python
r"https?://[\w\-\.\@:%_\+~#=\/\?&;,'()\[\]]+"
```

**Features:**
- Supports HTTP and HTTPS
- Captures query parameters, fragments, and complex paths
- Normalizes URLs (removes duplicates, trailing punctuation)

**Returns:** List of unique, normalized URLs

##### `normalize_url(url: str) -> str`
Normalizes URLs for consistent matching.

**Normalization Steps:**
1. Strip whitespace and trailing punctuation (`.`, `,`, `;`, `)`)
2. Remove URL fragments (`#section`)
3. Lowercase scheme and domain
4. Remove default ports (`:80` for HTTP, `:443` for HTTPS)
5. Remove trailing slash (except root URLs)

**Example:**
```python
normalize_url("HTTPS://Example.COM:443/path/")
→ "https://example.com/path"
```

##### `enrich_urls_for_email_async(email_id: str, max_per_email: int = 50, max_workers: int = 10)`
Main async function for processing URLs in an email.

**Logic Flow:**

```
1. Extract URLs from email body
   ↓
2. For each URL:
   │
   ├─ STEP 1: Check if URL exists in threat feeds
   │  │        (source_feed != 'email')
   │  ├─ YES → Set risk_score = 100
   │  │        Link to email
   │  │        Move to next URL
   │  │
   │  └─ NO → Continue to Step 2
   │
   ├─ STEP 2: Check if URL exists from email source
   │  │        (source_feed = 'email')
   │  ├─ YES → Recalculate risk_score
   │  │        Link to email
   │  │        Move to next URL
   │  │
   │  └─ NO → Continue to Step 3
   │
   └─ STEP 3: URL is new → Enrich in parallel
              ↓
              Async enrichment (multiple URLs at once)
              ↓
              Calculate risk_score
              ↓
              Insert into enriched_threats
              ↓
              Link to email

3. Calculate email risk_score = MAX(all URL scores)
   ↓
4. Update emails table
   ↓
5. Report risk level
```

**Parameters:**
- `email_id`: Email message ID
- `max_per_email`: Max URLs to process per email (default: 50)
- `max_workers`: Thread pool size for parallel enrichment (default: 10)

**Returns:** Number of URLs processed

**Performance:**
- URLs enriched in parallel using `asyncio.gather()`
- ThreadPoolExecutor for concurrent network operations
- Race condition protection for duplicate URL inserts

#### Risk Scoring

##### `calculate_and_set_url_risk_score(url_id: int)`
Calculates and updates risk score for a URL.

**Logic:**
```python
if source_feed != 'email':
    risk_score = 100  # External threat feed
else:
    risk_score = scoring.calculate_risk_score(...)  # Calculate
```

**Returns:** Calculated risk score

##### `update_email_risk_score(email_id: str, risk_score: int = None)`
Updates email risk score.

**If `risk_score=None`:**
```sql
SELECT MAX(et.risk_score)
FROM email_urls eu
JOIN enriched_threats et ON eu.url_id = et.id
WHERE eu.email_id = ?
```

**If `risk_score` provided:** Sets value directly

#### Database Management

##### `setup_database()`
Ensures `threat_feeds.db` is properly initialized with all tables.

Uses `db.create_db()` to create:
- `emails` table
- `email_urls` junction table
- `enriched_threats` table

##### `save_email_to_db(msg_id, sender, subject, date, headers, body_plain, body_html, risk_score=0)`
Inserts email into database.

**Uses `INSERT OR IGNORE`** to prevent duplicates.

##### `link_email_to_url(email_id: str, url_id: int)`
Links email to URL via `email_urls` junction table.

**Uses `INSERT OR IGNORE`** to prevent duplicate links.

---

### 2. `api.py` (10 lines)

**Purpose:** FastAPI REST endpoints for email analysis

**Endpoints:**

#### `GET /detector/check`
Analyzes a specific email by ID.

**Query Parameters:**
- `email_id` (required): Email message ID

**Response:**
```json
{
  "email_id": "msg123",
  "result": "Scanned msg123: enriched 3 URLs"
}
```

**Process:**
1. Calls `analyze_email(email_id)`
2. Enriches URLs in email
3. Returns summary

**Usage:**
```bash
curl "http://localhost:8000/detector/check?email_id=msg123"
```

---

### 3. `scoring.py` (200 lines)

**Purpose:** Risk scoring algorithm implementation

Covered in detail in [Risk Scoring System](#risk-scoring-system) section.

---

## Gmail Integration

### OAuth 2.0 Setup

#### Prerequisites
1. Google Cloud Project with Gmail API enabled
2. OAuth 2.0 credentials (Desktop application type)
3. Download `credentials.json` from Google Cloud Console

#### Setup Steps

**1. Create Google Cloud Project**
```
1. Go to https://console.cloud.google.com/
2. Create new project: "Phishing Detector"
3. Enable Gmail API
4. Create OAuth 2.0 credentials (Desktop app)
5. Download credentials.json
```

**2. Configure OAuth Consent Screen**
```
1. User type: External (or Internal for workspace)
2. App name: "Phishing Detector"
3. Support email: your-email@gmail.com
4. Scopes: Add "Gmail Read-only" scope
   - https://www.googleapis.com/auth/gmail.readonly
5. Test users: Add your Gmail address
```

**3. Install credentials.json**
```bash
# Place in detector directory
cp ~/Downloads/credentials.json app/detector/credentials.json
```

**4. First-time Authentication**
```bash
# Run authentication flow
python -m app.detector.core --authenticate

# Or during bootstrap
python -m app.detector.core --bootstrap
```

**5. Authentication Flow**
```
1. Browser opens with Google OAuth consent screen
2. Select Gmail account
3. Review permissions (read-only access)
4. Click "Allow"
5. Redirect to http://localhost:8080
6. token.json created automatically
```

### OAuth Files

**`credentials.json`** (OAuth client secrets)
- Contains: `client_id`, `client_secret`, `redirect_uris`
- Source: Google Cloud Console
- **Keep secure** - don't commit to git

**`token.json`** (User access token)
- Contains: `access_token`, `refresh_token`, `expiry`
- Generated: First OAuth flow
- Persists: Between sessions
- Auto-refreshes: When access token expires

### Troubleshooting OAuth

**"Port 8080 already in use"**
```bash
# Check what's using port 8080
lsof -i :8080

# Kill process or use manual flow
# Manual flow automatically triggers if port unavailable
```

**"Invalid grant" error**
```bash
# Token expired or revoked - delete and re-auth
rm app/detector/token.json
python -m app.detector.core --authenticate
```

**"Access blocked" error**
```
1. Verify app not in production mode (use testing mode)
2. Add your email to "Test users" in OAuth consent screen
3. Or publish app (requires verification for production)
```

---

## URL Extraction and Processing

### URL Extraction

**Regex Pattern Breakdown:**
```python
r"https?://[\w\-\.\@:%_\+~#=\/\?&;,'()\[\]]+"
```

**Matches:**
- `https?://` - HTTP or HTTPS
- `[\w\-\.]+` - Domain characters
- `\@:%_\+~#=` - Special URL characters
- `\/\?&;,'()\[\]` - Path, query, fragment characters

**Example Matches:**
```
✓ https://example.com
✓ http://sub.domain.com/path?query=value
✓ https://example.com:8080/page#section
✓ https://user:pass@example.com
✓ https://example.com/path?a=1&b=2
```

**Does NOT Match:**
```
✗ ftp://example.com (not HTTP/HTTPS)
✗ example.com (missing scheme)
✗ mailto:user@example.com (different protocol)
```

### URL Normalization

**Purpose:** Ensure consistent URL representation for deduplication and matching

**Normalization Rules:**

| Input | Output | Reason |
|-------|--------|--------|
| `HTTPS://Example.COM` | `https://example.com` | Lowercase scheme/domain |
| `http://example.com:80/` | `http://example.com` | Remove default port |
| `https://example.com:443/` | `https://example.com` | Remove default port |
| `https://example.com/path/` | `https://example.com/path` | Remove trailing slash |
| `https://example.com/#section` | `https://example.com/` | Remove fragment |
| `https://example.com/path.` | `https://example.com/path` | Remove trailing punctuation |

**Implementation:**
```python
from urllib.parse import urlparse, urlunparse

def normalize_url(url: str) -> str:
    # Strip whitespace and trailing punctuation
    url = url.strip().rstrip('.,;)')
    
    # Remove fragment
    if '#' in url:
        url = url.split('#')[0]
    
    # Parse URL
    parsed = urlparse(url)
    
    # Normalize scheme and netloc
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Remove default ports
    if ':80' in netloc and scheme == 'http':
        netloc = netloc.replace(':80', '')
    elif ':443' in netloc and scheme == 'https':
        netloc = netloc.replace(':443', '')
    
    # Normalize path
    path = parsed.path
    if path and path != '/' and path.endswith('/'):
        path = path.rstrip('/')
    elif not path:
        path = '/'
    
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ''))
```

### URL Processing Logic

**Three-Step Logic:**

#### Step 1: Check Threat Feeds
```python
cur.execute(
    'SELECT id, source_feed, risk_score FROM enriched_threats '
    'WHERE url = ? AND source_feed != ?',
    (normalized_url, 'email')
)
threat_match = cur.fetchone()

if threat_match:
    # Known threat - maximum risk
    calculate_and_set_url_risk_score(url_id)  # Sets to 100
    link_email_to_url(email_id, url_id)
    return  # Done
```

**Why:** If URL exists in PhishTank, URLhaus, or OpenPhish, it's a confirmed threat.

#### Step 2: Check Existing Email URLs
```python
cur.execute(
    'SELECT id FROM enriched_threats '
    'WHERE url = ? AND source_feed = ?',
    (normalized_url, 'email')
)
email_match = cur.fetchone()

if email_match:
    # Previously seen in emails - recalculate
    risk_score = calculate_and_set_url_risk_score(url_id)
    link_email_to_url(email_id, url_id)
    return  # Done
```

**Why:** Avoid re-enriching URLs we've already processed from other emails.

#### Step 3: Enrich New URLs
```python
# Async enrichment of multiple new URLs
tasks = [
    enrich_module.enrich_url_async(url, source_feed='email', source_id=email_id)
    for url in urls_to_enrich
]

results = await asyncio.gather(*tasks, return_exceptions=True)

for result in results:
    enrich_module.insert_enriched_data(THREAT_FEEDS_DB_PATH, result)
    risk_score = calculate_and_set_url_risk_score(url_id)
    link_email_to_url(email_id, url_id)
```

**Why:** New URLs need full enrichment (DNS, WHOIS, GeoIP, SSL, HTTP checks).

---

## Risk Scoring System

### Scoring Components

**Total Score Range:** 0-100 (higher = more risky)

#### 1. Liveness (0-35 points)
**Measures:** Site availability and HTTP response

**Scoring:**
```python
HTTP 200, 301, 302, 307, 308  → 35 pts (Fully operational)
HTTP 401, 403, 405, 429, 451  → 28 pts (Protected/restricted)
HTTP 5xx (500-599)            → 20 pts (Server error)
HTTP 404, 410                 → 12 pts (Not found)
Other                         → 10 pts (Unknown status)
```

**Fallback (no HTTP status):**
```python
online = 'yes'  → 20 pts
online = 'no'   → 10 pts
```

**Rationale:** Active sites pose higher risk than offline ones.

#### 2. Recency (0-25 points)
**Measures:** Days since URL was last seen in threat feeds

**Scoring:**
```python
≤3 days    → 25 pts (Very recent)
4-7 days   → 20 pts (Recent)
8-14 days  → 15 pts (Somewhat recent)
15-30 days → 10 pts (Older)
>30 days   → 5 pts  (Old)
No data    → 5 pts  (Unknown)
```

**Rationale:** Recently reported threats are more likely still active.

#### 3. Domain Age (0-20 points)
**Measures:** Days since domain was created (from WHOIS)

**Scoring:**
```python
≤7 days     → 20 pts (Brand new - highly suspicious)
8-30 days   → 15 pts (Very new)
31-90 days  → 10 pts (New)
>90 days    → 5 pts  (Established)
No data     → 8 pts  (Unknown)
```

**Rationale:** Phishing campaigns often use newly registered domains.

#### 4. TLD/Platform (0-10 points)
**Measures:** Top-level domain and hosting platform

**High-Risk TLDs:**
```python
.zip, .mov, .top, .cc, .icu, .xyz, .click, .info → 10 pts
```

**Ephemeral Platforms:**
```python
.vercel.app, .web.app, .github.io, .pages.dev, .netlify.app → +risk
```

**Scoring:**
```python
High-risk TLD                → 10 pts (Always max)
Common TLD + ephemeral       → 8 pts
Common TLD                   → 5 pts
Other TLD + ephemeral        → 10 pts
Other TLD                    → 7 pts
```

**Rationale:** Certain TLDs and free hosting platforms are favored by attackers.

#### 5. Keywords (0-10 points)
**Measures:** Presence of suspicious keywords in URL

**Suspicious Keywords:**
```python
'login', 'verify', 'secure', 'update', 'invoice', 'mfa',
'password', 'wallet', 'bank', 'microsoft', 'office365', 'att'
```

**Scoring:**
```python
Any keyword present → 10 pts
No keywords         → 0 pts
```

**Rationale:** Phishing URLs often mimic login pages or urgent actions.

### Risk Levels

**Thresholds:**
```python
85-100 → Critical  🚨
70-84  → High      ⚠️
50-69  → Medium    ⚡
0-49   → Low       ✓
```

### Scoring Examples

#### Example 1: Known Phishing Site
```python
URL: https://secure-login-microsoft.zip/verify
Source: PhishTank feed

Result: risk_score = 100 (external threat feed)
Level: CRITICAL 🚨
```

#### Example 2: Suspicious New Domain
```python
URL: https://bank-update.click/login
HTTP: 200 (online)
Last Seen: Today
Domain Age: 2 days
TLD: .click (high-risk)
Keywords: "bank", "login"

Calculation:
  Liveness: 35
  Recency: 25
  Domain Age: 20
  TLD: 10
  Keywords: 10
  ──────────
  Total: 100

Result: risk_score = 100
Level: CRITICAL 🚨
```

#### Example 3: Legitimate Site
```python
URL: https://github.com/user/repo
HTTP: 200
Last Seen: Not in feeds (no recent reports)
Domain Age: 17 years (created 2008)
TLD: .com
Keywords: None

Calculation:
  Liveness: 35
  Recency: 5
  Domain Age: 5
  TLD: 5
  Keywords: 0
  ──────────
  Total: 50

Result: risk_score = 50
Level: MEDIUM ⚡
```

#### Example 4: Offline Phishing Site
```python
URL: https://old-phish.xyz/secure
HTTP: 404 (not found)
Last Seen: 45 days ago
Domain Age: 90 days
TLD: .xyz (high-risk)
Keywords: "secure"

Calculation:
  Liveness: 12
  Recency: 5
  Domain Age: 10
  TLD: 10
  Keywords: 10
  ──────────
  Total: 47

Result: risk_score = 47
Level: LOW ✓
```

### Email Risk Score

**Email risk_score = MAX(all linked URL risk_scores)**

**Examples:**
```python
Email with URLs:
  - https://google.com → 45
  - https://github.com → 50
  - https://phishing.zip → 100

Email risk_score = 100 (maximum of all)
Level: CRITICAL 🚨
```

---

## API Endpoints

### REST API (FastAPI)

**Base URL:** `http://localhost:8000/detector`

#### `GET /check`
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

**Process:**
1. Calls `analyze_email(email_id)`
2. Extracts URLs from email
3. Enriches URLs (async)
4. Calculates risk scores
5. Updates database
6. Returns summary

**Error Responses:**
```json
{
  "detail": "Email not found"
}
```

---

## Usage Examples

### Command-Line Interface

#### 1. Initial Setup
```bash
# Create database schema
python -m app.detector.core --setup-db

# Authenticate with Gmail (first time)
python -m app.detector.core --authenticate
```

#### 2. Fetch Emails
```bash
# Fetch 25 recent emails (default)
python -m app.detector.core --fetch

# Fetch 100 emails
python -m app.detector.core --fetch 100

# Use custom credentials file
python -m app.detector.core --fetch --credentials /path/to/credentials.json
```

#### 3. Enrich URLs in Emails
```bash
# Enrich URLs for specific email
python -m app.detector.core --enrich-email msg123

# Enrich all emails in database
python -m app.detector.core --enrich-all
```

#### 4. Bootstrap (All-in-One)
```bash
# Setup DB + Fetch emails + Enrich URLs
python -m app.detector.core --bootstrap

# Fetch more emails during bootstrap
python -m app.detector.core --bootstrap --max-fetch 100
```

#### 5. Seed Sample Data
```bash
# Insert test email for development
python -m app.detector.core --seed-sample
```

### Python API

#### Example 1: Fetch and Process Emails
```python
from app.detector.core import (
    setup_database,
    fetch_and_store_recent_emails,
    enrich_urls_for_email
)

# Setup
setup_database()

# Fetch emails
email_ids = fetch_and_store_recent_emails(max_results=10)

# Process each email
for email_id in email_ids:
    num_urls = enrich_urls_for_email(email_id)
    print(f"Processed {num_urls} URLs in {email_id}")
```

#### Example 2: Check Email Risk Score
```python
import sqlite3
from pathlib import Path

DB_PATH = Path('app/database/threat_feeds.db')
conn = sqlite3.connect(DB_PATH)
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

conn.close()
```

#### Example 3: Get URLs from Email
```python
import sqlite3
from pathlib import Path

DB_PATH = Path('app/database/threat_feeds.db')
email_id = 'msg123'

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Get all URLs linked to email
cur.execute("""
    SELECT et.url, et.risk_score, et.source_feed, et.online
    FROM email_urls eu
    JOIN enriched_threats et ON eu.url_id = et.id
    WHERE eu.email_id = ?
    ORDER BY et.risk_score DESC
""", (email_id,))

for url, risk, source, online in cur.fetchall():
    print(f"{risk}/100 | {online} | {source} | {url}")

conn.close()
```

### REST API Usage

#### Using curl
```bash
# Check email
curl "http://localhost:8000/detector/check?email_id=msg123"

# Response
{
  "email_id": "msg123",
  "result": "Scanned msg123: enriched 3 URLs"
}
```

#### Using Python requests
```python
import requests

response = requests.get(
    'http://localhost:8000/detector/check',
    params={'email_id': 'msg123'}
)

result = response.json()
print(result)
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Gmail OAuth (optional - uses credentials.json by default)
# GMAIL_CREDENTIALS_PATH=/path/to/credentials.json

# Database path (optional - uses default)
# THREAT_FEEDS_DB_PATH=/path/to/threat_feeds.db

# Threat feed API keys (for enrichment module)
PHISHTANK_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here
```

### OAuth Configuration

**credentials.json Structure:**
```json
{
  "installed": {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "project_id": "phishing-detector",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_uris": ["http://localhost:8080"]
  }
}
```

**Required Scopes:**
```python
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
```

### Performance Tuning

**URL Processing:**
```python
# In enrich_urls_for_email_async()
max_per_email = 50      # Max URLs per email
max_workers = 10        # Thread pool size for enrichment
```

**Adjust for performance:**
- **Increase `max_workers`** for faster parallel processing (10-20 typical)
- **Decrease `max_per_email`** if emails have too many URLs (e.g., newsletters)

---

## Troubleshooting

### Gmail Authentication Issues

**Problem:** "credentials.json not found"
```bash
# Solution: Ensure file exists in correct location
ls app/detector/credentials.json

# If missing, download from Google Cloud Console
# Place in: app/detector/credentials.json
```

**Problem:** "OAuth flow failed"
```bash
# Solution 1: Check port 8080 is available
lsof -i :8080

# Solution 2: Delete old token and re-authenticate
rm app/detector/token.json
python -m app.detector.core --authenticate

# Solution 3: Use manual code entry
# Follow on-screen instructions and paste redirect URL
```

**Problem:** "Insufficient permissions"
```
# Solution: Verify OAuth consent screen settings
1. Check Gmail API is enabled
2. Verify scope includes gmail.readonly
3. Add your email to test users (if in testing mode)
4. Or publish app (requires verification)
```

### URL Extraction Issues

**Problem:** URLs not extracted from email
```python
# Debug: Check email body content
import sqlite3
conn = sqlite3.connect('app/database/threat_feeds.db')
cur = conn.cursor()
cur.execute("SELECT body_plain, body_html FROM emails WHERE id = ?", ('msg123',))
plain, html = cur.fetchone()
print("Plain:", plain)
print("HTML:", html)
conn.close()

# Verify URLs exist in text
import re
pattern = r"https?://[\w\-\.\@:%_\+~#=\/\?&;,'()\[\]]+"
urls = re.findall(pattern, plain + html)
print("Found URLs:", urls)
```

**Problem:** Duplicate URLs
```
# Normalization should handle this, but verify:
from app.detector.core import normalize_url

url1 = "https://Example.COM:443/path/"
url2 = "https://example.com/path"

print(normalize_url(url1))  # Should match
print(normalize_url(url2))
```

### Risk Scoring Issues

**Problem:** All emails show risk_score = 0
```bash
# Check if enrichment ran
sqlite3 app/database/threat_feeds.db \
  "SELECT COUNT(*) FROM email_urls"

# If 0, URLs not linked - run enrichment
python -m app.detector.core --enrich-all
```

**Problem:** Risk scores seem incorrect
```python
# Debug scoring for specific URL
from app.detector import scoring

score_breakdown = scoring.get_score_breakdown(
    url="https://example.com",
    http_status_code=200,
    online_status="yes",
    last_seen="2024-10-11",
    creation_date="2024-10-01",
    tld="com"
)

print(score_breakdown)
# Shows individual component scores
```

### Database Issues

**Problem:** "database is locked"
```bash
# Close any SQLite browser applications
# Check for stale WAL files
ls app/database/*.db-wal

# If present, remove (safe if no other processes running)
rm app/database/*.db-wal
rm app/database/*.db-shm
```

**Problem:** Emails table doesn't exist
```bash
# Recreate database schema
python -m app.detector.core --setup-db

# Or use db module directly
python -m app.database.db
```

### Performance Issues

**Problem:** Enrichment too slow
```bash
# Solution 1: Reduce max URLs per email
# Edit core.py, line with enrich_urls_for_email_async()
# Change: max_per_email = 20  (from 50)

# Solution 2: Increase parallel workers
# Change: max_workers = 20  (from 10)

# Solution 3: Skip page content enrichment
# (Modify enrich.py to disable page fetching)
```

**Problem:** Too many API requests
```
# Rate limiting in scoring.py and enrich.py
# WHOIS: 1 second delay (hard-coded)
# HTTP: 0.5 second delay

# To reduce:
# - Use GeoIP databases (offline lookups)
# - Process fewer emails at once
# - Skip WHOIS (don't install python-whois)
```

---

## Summary

### Key Features
✅ Gmail OAuth 2.0 integration with auto-refresh
✅ Async URL enrichment for performance
✅ Multi-factor risk scoring (0-100 scale)
✅ Automatic threat feed matching
✅ REST API for programmatic access
✅ Comprehensive CLI for management

### Workflow
1. **Setup:** Authenticate with Gmail, create database
2. **Fetch:** Retrieve recent emails from Gmail
3. **Extract:** Parse URLs from email bodies
4. **Process:** Check threat feeds, enrich new URLs
5. **Score:** Calculate risk scores (per URL and per email)
6. **Store:** Link emails to URLs, update risk scores
7. **Access:** Query via API or database

### Performance
- **Async enrichment:** 10+ URLs processed in parallel
- **Smart caching:** Existing URLs not re-enriched
- **Race condition protection:** Safe concurrent access
- **Typical speed:** ~5-10 seconds per email (with 5-10 URLs)

### Best Practices
1. Run `--authenticate` before starting web app
2. Use `--bootstrap` for initial setup
3. Monitor risk scores regularly
4. Update threat feeds daily
5. Review high-risk emails manually

---

**Last Updated:** October 12, 2025  
**Module Version:** 1.0  
**Dependencies:** google-auth, google-auth-oauthlib, google-api-python-client, aiohttp
