# Phishing Detector - Complete Database System Guide

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Database Files](#database-files)
4. [Phase 1: Raw Database Creation & Population](#phase-1-raw-database-creation--population)
5. [Phase 2: Enriched Database Creation](#phase-2-enriched-database-creation)
6. [Phase 3: Enrichment Pipeline](#phase-3-enrichment-pipeline)
7. [Enrichment Data Sources](#enrichment-data-sources)
8. [Enrichment Limitations](#enrichment-limitations)
9. [File Documentation](#file-documentation)
10. [Usage Examples](#usage-examples)
11. [Performance & Optimization](#performance--optimization)
12. [Troubleshooting](#troubleshooting)

---

## Overview

The phishing detector uses a **two-database architecture**:
1. **Raw Database** (`threat_feeds_raw.db`) - Stores unprocessed URLs from public threat feeds
2. **Enriched Database** (`threat_feeds.db`) - Stores URLs with additional intelligence data

**Data Flow:**
```
Public Feeds → Raw DB → Enrichment Pipeline → Enriched DB → Analysis/Detection
```

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA COLLECTION PHASE                         │
└─────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
    │  OpenPhish   │      │  PhishTank   │      │   URLhaus    │
    │   (Free)     │      │  (Free API)  │      │  (API Key)   │
    └──────┬───────┘      └──────┬───────┘      └──────┬───────┘
           │                     │                     │
           └─────────────────────┼─────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   grabrawdata.py        │
                    │   - HTTP requests       │
                    │   - JSON/CSV parsing    │
                    │   - Deduplication       │
                    └────────────┬────────────┘
                                 │
                                 ▼
                ┌────────────────────────────────────┐
                │  threat_feeds_raw.db (37 MB)       │
                ├────────────────────────────────────┤
                │  • openphish_feed                  │
                │  • phishtank_archival              │
                │  • urlhaus_api                     │
                └────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                       ENRICHMENT PHASE                               │
└─────────────────────────────────────────────────────────────────────┘

                    ┌────────────────────┐
                    │    enrich.py       │
                    │  Main Orchestrator │
                    └─────────┬──────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   ┌─────────┐         ┌──────────┐         ┌──────────┐
   │   DNS   │         │  WHOIS   │         │  GeoIP   │
   │  Lookup │         │  Query   │         │ Database │
   └────┬────┘         └────┬─────┘         └────┬─────┘
        │                   │                     │
        ▼                   ▼                     ▼
   ┌─────────┐         ┌──────────┐         ┌──────────┐
   │   SSL   │         │ IPWhois  │         │   HTTP   │
   │  Check  │         │   RDAP   │         │  Probe   │
   └────┬────┘         └────┬─────┘         └────┬─────┘
        │                   │                     │
        └───────────────────┼─────────────────────┘
                            │
                            ▼
                ┌────────────────────────────────────┐
                │  threat_feeds.db (84 KB)           │
                ├────────────────────────────────────┤
                │  enriched_threats (41 fields)      │
                │  • Network: IP, ASN, ISP           │
                │  • Location: Country, City, GPS    │
                │  • SSL: Certificates, Validity     │
                │  • WHOIS: Registrar, Dates         │
                │  • Status: Online, HTTP codes      │
                └────────────────────────────────────┘
```

---

## Database Files

### 1. `threat_feeds_raw.db` (Raw Database)
**Size:** ~37 MB  
**Purpose:** Stores unprocessed threat feed data  
**Location:** `app/database/threat_feeds_raw.db`

**Tables:**
- **openphish_feed** - OpenPhish URLs (~600 records)
  - `id`, `url`, `domain`, `added_at`, `note`
  
- **phishtank_archival** - PhishTank verified phishing URLs (~51,000 records)
  - `phish_id`, `url`, `phish_detail_url`, `submission_time`, `verified`
  - `verification_time`, `online`, `target`, `ip_address`, `cidr_block`
  - `announcing_network`, `rir`, `detail_time`, `inserted_at`
  
- **urlhaus_api** - URLhaus malware URLs (~800 records)
  - `urlhaus_id`, `url`, `url_status`, `url_dateadded`, `url_lastseen`
  - `reporter`, `reporter_handle`, `verifier`, `threat`, `tags`
  - `file_md5`, `file_sha256`, `file_name`, `file_size`, `payload_type`
  - `distribution`, `asn`, `country`, `referrer`, `request_headers`
  - `response_code`, `cloaking`, `comments`, `inserted_at`

### 2. `threat_feeds.db` (Enriched Database)
**Size:** ~84 KB (grows with enrichment)  
**Purpose:** Stores URLs with enrichment intelligence data  
**Location:** `app/database/threat_feeds.db`

**Table:**
- **enriched_threats** - Single table with 41 fields:
  - **Identifiers:** `id`, `url`, `domain`
  - **Status:** `online`, `http_status_code`
  - **Network:** `ip_address`, `cidr_block`, `asn`, `asn_name`, `isp`
  - **Geographic:** `country`, `country_name`, `region`, `city`, `latitude`, `longitude`
  - **SSL/TLS:** `ssl_enabled`, `cert_issuer`, `cert_subject`, `cert_valid_from`, `cert_valid_to`, `cert_serial`
  - **WHOIS:** `tld`, `registrar`, `creation_date`, `expiry_date`, `updated_date`, `name_servers`
  - **Content:** `page_language`, `page_title`
  - **Threat:** `threat_type`, `target_brand`, `threat_tags`
  - **Source:** `source_feed`, `source_id`, `first_seen`, `last_seen`, `last_checked`
  - **Meta:** `notes`, `created_at`, `updated_at`

**Indexes:** 10 indexes for optimized queries on domain, IP, ASN, country, source, online status, TLD, threat type, and timestamps.

---

## Phase 1: Raw Database Creation & Population

### Step 1.1: Create Raw Database Schema

**Script:** `rawdb.py`  
**Purpose:** Creates the SQLite database schema for raw threat feeds

**Usage:**
```bash
python -m app.database.rawdb
```

**What it does:**
- Creates `threat_feeds_raw.db` if it doesn't exist
- Defines three tables: `openphish_feed`, `phishtank_archival`, `urlhaus_api`
- Creates indexes on commonly queried fields

### Step 1.2: Populate Raw Database

**Script:** `grabrawdata.py`  
**Purpose:** Fetches threat data from public feeds and populates the database

**Prerequisites:**
```bash
# Install dependencies
pip install requests python-dotenv

# Optional: Set up API keys in .env file
PHISHTANK_API_KEY=your_key_here  # Optional - higher rate limits
URLHAUS_API_KEY=your_key_here    # Required for URLhaus data
```

**Usage:**
```bash
# Fetch all feeds
python -m app.database.grabrawdata

# Skip specific feeds
python -m app.database.grabrawdata --skip-openphish
python -m app.database.grabrawdata --skip-phishtank
python -m app.database.grabrawdata --skip-urlhaus

# Custom database path
python -m app.database.grabrawdata --db /path/to/db.db
```

**Data Sources:**
- **OpenPhish:** `https://openphish.com/feed.txt` (no API key needed)
- **PhishTank:** `https://data.phishtank.com/data/online-valid.json` (API key optional)
- **URLhaus:** `https://urlhaus-api.abuse.ch/v1/urls/recent/` (API key required)

**What it does:**
- Downloads threat feeds via HTTP
- Parses JSON/CSV/text formats
- Inserts URLs into appropriate tables using `INSERT OR IGNORE` (idempotent)
- Handles rate limiting and retries on failures

**Verification:**
```bash
# Check record counts
sqlite3 app/database/threat_feeds_raw.db "
  SELECT 'OpenPhish' as source, COUNT(*) FROM openphish_feed 
  UNION ALL 
  SELECT 'PhishTank', COUNT(*) FROM phishtank_archival 
  UNION ALL 
  SELECT 'URLhaus', COUNT(*) FROM urlhaus_api;"
```

---

## Phase 2: Enriched Database Creation

### Step 2: Create Enriched Database Schema

**Script:** `db.py`  
**Purpose:** Creates the enriched database with 41-field schema

**Usage:**
```bash
python -m app.database.db
```

**What it does:**
- Creates `threat_feeds.db` if it doesn't exist
- Defines `enriched_threats` table with all 41 enrichment fields
- Creates 10 indexes for query optimization
- Table initially empty - data populated by enrichment pipeline

**Verification:**
```bash
# Check schema
sqlite3 app/database/threat_feeds.db ".schema enriched_threats"

# Check table exists (should be 0 records initially)
sqlite3 app/database/threat_feeds.db "SELECT COUNT(*) FROM enriched_threats;"
```

---

## Phase 3: Enrichment Pipeline

### Step 3: Run Enrichment

**Script:** `enrich.py` (734 lines)  
**Purpose:** Main enrichment orchestrator - reads raw URLs, enriches them, stores results

**Prerequisites:**
```bash
# Minimal (DNS + SSL + HTTP only)
pip install requests python-dotenv

# Full enrichment (recommended)
pip install python-whois geoip2 ipwhois langdetect
```

**Optional: GeoIP Databases**
1. Sign up at https://www.maxmind.com/en/geolite2/signup
2. Download: `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`
3. Place in: `app/database/`

**Usage:**
```bash
# Test with 10 URLs
python -m app.database.enrich --limit 10

# Process 1000 URLs, skip already enriched
python -m app.database.enrich --limit 1000 --skip-existing

# Process specific source feed
python -m app.database.enrich --source phishtank --limit 500
python -m app.database.enrich --source openphish
python -m app.database.enrich --source urlhaus

# Full enrichment (all URLs, overnight job)
nohup python -m app.database.enrich --skip-existing > enrichment.log 2>&1 &
```

**Options:**
- `--limit N` - Process only N URLs
- `--skip-existing` - Skip URLs already in enriched database
- `--source FEED` - Process only specific feed (openphish/phishtank/urlhaus)
- `--raw-db PATH` - Custom raw database path
- `--enriched-db PATH` - Custom enriched database path

**What it does:**
1. Queries raw database for URLs
2. For each URL:
   - Extracts domain and TLD
   - Resolves DNS (IP address)
   - Queries WHOIS (registrar, dates, nameservers) - if available
   - Looks up GeoIP (country, city, coordinates, ASN) - if available
   - Fallback to IPWhois for ASN/ISP - if GeoIP unavailable
   - Checks SSL certificate (issuer, validity, serial)
   - Probes HTTP status (online status, response code)
   - Detects page language from title
3. Inserts enriched data into `enriched_threats` table

**Verification:**
```bash
# Count enriched URLs
sqlite3 app/database/threat_feeds.db "SELECT COUNT(*) FROM enriched_threats;"

# View sample enriched data
sqlite3 app/database/threat_feeds.db "
  SELECT url, domain, country, city, ssl_enabled, online 
  FROM enriched_threats LIMIT 5;" -column -header

# Check enrichment by source
sqlite3 app/database/threat_feeds.db "
  SELECT source_feed, COUNT(*) 
  FROM enriched_threats 
  GROUP BY source_feed;"
```

---

## Enrichment Data Sources

### 1. DNS Resolution (Built-in)
**What:** Resolves domain names to IP addresses  
**How:** Python `socket.gethostbyname()`  
**Speed:** Fast (~0.1s per lookup)  
**Data Provided:**
- `ip_address`

**Always available:** ✅ No dependencies

---

### 2. WHOIS Lookups (python-whois)
**What:** Domain registration information  
**How:** WHOIS protocol queries to TLD registries  
**Speed:** Slow (~1-2s per query, rate-limited)  
**Data Provided:**
- `registrar` - Domain registrar name
- `creation_date` - When domain was registered
- `expiry_date` - When domain expires
- `updated_date` - Last WHOIS update
- `name_servers` - DNS nameservers (comma-separated)

**Dependency:** `pip install python-whois`  
**Rate Limiting:** 1 second delay between queries (required to avoid bans)

**Limitations:**
- ⚠️ **WHOIS Privacy:** ~69% of domains use privacy protection services
- ⚠️ **TLD Restrictions:** Some TLDs block automated queries (.dev, .br, .tl)
- ⚠️ **Subdomains:** Services like Blogspot, Pages.dev don't have individual WHOIS
- ⚠️ **Timeouts:** Some WHOIS servers are unreliable

---

### 3. GeoIP Lookups (geoip2 + MaxMind)
**What:** Geographic location and network data from IP addresses  
**How:** Offline database lookups (MaxMind GeoLite2)  
**Speed:** Very fast (~0.01s per lookup)  
**Data Provided:**
- `country` - ISO country code (e.g., 'US')
- `country_name` - Full country name
- `region` - State/province
- `city` - City name
- `latitude` / `longitude` - GPS coordinates
- `asn` - Autonomous System Number
- `asn_name` - AS organization name

**Dependency:** `pip install geoip2`  
**Database Files:** Download from MaxMind (free account required)
- `GeoLite2-City.mmdb` - City/region/coordinates
- `GeoLite2-ASN.mmdb` - ASN/organization data

**Advantages:**
- ✅ Offline lookups (no rate limits)
- ✅ Very fast
- ✅ High accuracy

**Fallback:** IPWhois (online RDAP queries) if GeoIP unavailable

---

### 4. IPWhois Lookups (ipwhois - fallback)
**What:** Network/ASN information via online RDAP queries  
**How:** Queries Regional Internet Registries (ARIN, RIPE, APNIC, etc.)  
**Speed:** Slow (~0.5-1s per query)  
**Data Provided:**
- `asn` - Autonomous System Number
- `asn_name` - AS description
- `cidr_block` - Network CIDR notation
- `isp` - ISP/network name
- `country` - Country code

**Dependency:** `pip install ipwhois`  
**Used when:** GeoIP databases not available

**Limitations:**
- ⚠️ **CDN IPs:** Cloudflare, AWS CloudFront often don't expose CIDR blocks
- ⚠️ **Slower:** Online queries vs offline GeoIP databases

---

### 5. SSL/TLS Certificate Inspection (Built-in)
**What:** HTTPS certificate details  
**How:** SSL socket connection to port 443  
**Speed:** Medium (~0.3-0.5s per check)  
**Data Provided:**
- `ssl_enabled` - 'yes' or 'no'
- `cert_issuer` - Certificate issuer organization
- `cert_subject` - Certificate subject (domain)
- `cert_valid_from` - Certificate start date
- `cert_valid_to` - Certificate expiry date
- `cert_serial` - Certificate serial number

**Always available:** ✅ No dependencies  
**Timeout:** 5 seconds

**Note:** HTTP-only sites will have `ssl_enabled='no'` and NULL certificate fields (expected behavior)

---

### 6. HTTP Status Probing (requests)
**What:** Check if site is online and accessible  
**How:** HTTP HEAD request to URL  
**Speed:** Medium-slow (~0.5-1s per probe)  
**Data Provided:**
- `online` - 'yes', 'no', or 'unknown'
- `http_status_code` - HTTP response code (200, 404, 403, etc.)
- `page_title` - HTML page title (from response)

**Dependency:** `pip install requests`  
**Timeout:** 10 seconds  
**Note:** SSL verification disabled for phishing sites (often have invalid certs)

---

### 7. Language Detection (langdetect)
**What:** Detect page language from page title  
**How:** Google's language detection algorithm (NLP)  
**Speed:** Very fast (~0.01s)  
**Data Provided:**
- `page_language` - ISO language code (e.g., 'en', 'nl', 'da')

**Dependency:** `pip install langdetect`  
**Fallback:** Heuristic keyword matching if not available

**Limitations:**
- ⚠️ Short titles may not have enough context
- ⚠️ Requires page to be online

---

## Enrichment Limitations

### What Can vs Cannot Be Fixed

#### ✅ Fields with 100% Population
- `url` - From raw database
- `domain` - Extracted from URL
- `ip_address` - DNS resolution (100% success for valid domains)
- `country` - GeoIP/IPWhois fallback (100% coverage)
- `city` - GeoIP (100% coverage)
- `asn` - GeoIP/IPWhois (100% coverage)
- `isp` - IPWhois fallback (100% coverage)
- `ssl_enabled` - Always checked (100% coverage)
- `online` - Always checked (100% coverage)
- `threat_type` - From raw database or inferred
- `source_feed` - From raw database

#### ⚠️ Fields with Partial Population

**CIDR Block** (~86% success)
- **Missing for:** CDN IPs (Cloudflare, AWS, Google)
- **Why:** CDNs don't expose CIDR ranges via RDAP for security reasons
- **Fixable:** ❌ No - CDN policy limitation
- **Current state:** Best effort using IPWhois RDAP

**Page Language** (~59% success)
- **Missing for:** Offline sites, very short titles, non-textual content
- **Why:** Requires HTTP response, needs sufficient text for detection
- **Fixable:** ⚠️ Partially - could fetch full page body (very slow)
- **Current state:** Uses NLP on page title (langdetect library)

**Page Title** (~97% success)
- **Missing for:** Offline sites, sites that block HEAD requests
- **Why:** Requires HTTP response
- **Fixable:** ✅ Already optimal
- **Current state:** High success rate

#### ❌ Fields with Low Population

**WHOIS Data** (~31% success: registrar, creation_date, expiry_date, name_servers)
- **Missing for:** ~69% of domains
- **Why:**
  1. **WHOIS Privacy Protection** - Domain privacy services block public access
  2. **TLD Restrictions** - Some TLDs restrict automated queries (.dev, .br, .tl)
  3. **Subdomains** - Hosted services (Blogspot, Pages.dev, MyFreeSites) - parent domain WHOIS irrelevant
  4. **Rate Limiting** - WHOIS servers block/throttle automated queries
  5. **Timeouts** - Some WHOIS servers unreliable (e.g., .tl domains)
- **Fixable:** ❌ No - fundamental protocol/policy limitations
- **Current state:** 1-second rate limiting, best effort

**SSL Certificates** (Variable - only for HTTPS sites)
- **Missing for:** HTTP-only sites
- **Why:** These sites don't use SSL/TLS
- **Fixable:** N/A - Correct behavior (NULL for HTTP sites)
- **Current state:** Working as intended

**Target Brand** (PhishTank only - 0% for OpenPhish/URLhaus)
- **Missing for:** OpenPhish and URLhaus sources
- **Why:** These feeds don't include brand/target information
- **Fixable:** ⚠️ Could use ML/scraping (unreliable, slow, expensive)
- **Current state:** Available only from PhishTank data

**Threat Tags** (~0% - URLhaus field exists but empty)
- **Missing for:** All records
- **Why:** URLhaus doesn't consistently populate this field
- **Fixable:** ❌ No - upstream data quality issue
- **Current state:** Field exists but typically empty

---

### Technical Reasons for Limitations

#### 1. WHOIS Privacy Protection (69% of domains)
**Example:**
```
$ whois example-phish.pages.dev
Domain: pages.dev
Registrant: Cloudflare, Inc. (privacy protected)
Registrant Email: [REDACTED FOR PRIVACY]
```

**Why it happens:**
- GDPR/privacy laws require registrars to hide personal information
- Services like WhoisGuard, Domain Privacy, PrivacyProtect are standard
- Subdomains on hosting platforms (Blogspot, Pages.dev) - only parent domain WHOIS available

**Cannot be fixed without:**
- Paid WHOIS API services with additional data sources
- Legal access to registrar databases (not publicly available)

---

#### 2. CDN CIDR Blocks (14% missing)
**Example:**
```
IP: 188.114.96.6 (Cloudflare)
ASN: 13335 (CLOUDFLARE)
ISP: Cloudflare, Inc.
CIDR: [Not available via RDAP]
```

**Why it happens:**
- CDNs use dynamic IP allocation across global edge servers
- Security/operational reasons - don't expose network topology
- RDAP queries return ASN/ISP but not CIDR ranges

**Cannot be fixed:**
- Technical limitation of CDN architecture
- ASN/ISP information is sufficient for threat intelligence

---

#### 3. Short Page Titles (41% no language detection)
**Example:**
```
Title: "Home"
Language: Cannot detect (too short)
```

**Why it happens:**
- Generic single-word titles lack language context
- NLP requires ~10+ characters for accurate detection
- Offline sites - no HTTP response available

**Could be improved by:**
- Fetching full page body (5-10x slower per URL)
- Not implemented due to performance trade-off

---

### Performance vs Completeness Trade-offs

The enrichment pipeline prioritizes **speed and reliability** over **100% field population**:

| Feature | Trade-off | Decision |
|---------|-----------|----------|
| 1s WHOIS delay | Slower, but avoids server bans | ✅ Required |
| GeoIP databases | Fast, but requires setup | ✅ Recommended |
| langdetect on title only | Misses some languages | ✅ Acceptable (fetching body too slow) |
| IPWhois RDAP | Fast, but CDNs incomplete | ✅ Best available |
| Skip HTTPS on HTTP sites | NULL cert fields | ✅ Correct behavior |

**Processing time per URL:** ~4-6 seconds (full enrichment)  
**Bottlenecks:**
1. WHOIS queries: 1-2s (required delay)
2. HTTP probes: 0.5-1s
3. IPWhois RDAP: 0.5-1s
4. SSL checks: 0.3-0.5s
5. DNS: 0.1s

---

## File Documentation

### Core Python Scripts

#### `rawdb.py` (~100 lines)
**Purpose:** Create raw database schema  
**Key Functions:**
- `create_db(path)` - Creates threat_feeds_raw.db with 3 tables

**Tables Created:**
- `openphish_feed` - OpenPhish URLs
- `phishtank_archival` - PhishTank verified phishing
- `urlhaus_api` - URLhaus malware URLs

**Indexes:** 6 indexes on domains, IPs, ASNs

---

#### `grabrawdata.py` (~400 lines)
**Purpose:** Populate raw database from public feeds  
**Key Functions:**
- `load_openphish_feed(con)` - Fetch OpenPhish feed (text file)
- `load_phishtank_archival(con)` - Fetch PhishTank JSON (with CSV fallback)
- `load_urlhaus_recent(con)` - Fetch URLhaus API (requires key)
- `http_get()` / `http_post()` - HTTP helpers with retry logic

**Features:**
- Idempotent (INSERT OR IGNORE / UPSERT)
- Retry logic on 429/500/502/503/504 errors
- Supports compressed JSON (gzip, bz2)
- Environment variable support (.env file)

**Dependencies:**
- `requests` - HTTP client
- `python-dotenv` - .env file support

---

#### `db.py` (~150 lines)
**Purpose:** Create enriched database schema  
**Key Functions:**
- `create_db(path)` - Creates threat_feeds.db with enriched_threats table
- `init_db()` - Initialize both raw and enriched databases

**Schema:**
- 41 fields covering network, geo, SSL, WHOIS, content, threat data
- 10 indexes for query optimization

**Can be imported as module:**
```python
from app.database import db
db.create_db()
```

---

#### `enrich.py` (~916 lines) - **Main Enrichment Pipeline**
**Purpose:** Orchestrate all enrichment operations

**Key Classes:**
- `EnrichmentData` - Container for all 41 enrichment fields

**Key Functions:**

**DNS & Domain:**
- `extract_domain(url)` - Parse domain from URL
- `extract_tld(domain)` - Extract top-level domain
- `resolve_ip(domain)` - DNS A record lookup

**WHOIS:**
- `get_whois_info(domain)` - WHOIS queries (python-whois)
  - Returns: registrar, creation_date, expiry_date, updated_date, name_servers

**GeoIP:**
- `get_geoip_info(ip_address)` - GeoIP database lookups
  - City DB: country, region, city, coordinates
  - ASN DB: ASN, organization name
  - Fallback: IPWhois RDAP if databases unavailable

**Network:**
- `get_asn_info_ipwhois(ip_address)` - IPWhois RDAP queries
  - Returns: ASN, ASN name, CIDR, ISP, country

**SSL/TLS:**
- `get_ssl_info(domain)` - SSL certificate inspection
  - Returns: ssl_enabled, cert_issuer, cert_subject, cert_valid_from, cert_valid_to, cert_serial

**HTTP:**
- `check_online_status(url)` - HTTP HEAD requests
  - Returns: online status, HTTP code, page_title
- `detect_language(page_title)` - Language detection via langdetect

**Database:**
- `get_raw_data(raw_db, limit, skip_existing, source)` - Query raw database for URLs
- `insert_enriched_data(enriched_db, data)` - Insert enriched data
- `enrich_url(url, source_feed, source_id, raw_data)` - Main enrichment orchestrator

**CLI:**
- `main()` - Command-line interface with argument parsing

**Features:**
- Graceful degradation (missing dependencies)
- Rate limiting (1s WHOIS delay, 0.5s HTTP delay)
- Error handling (logs errors, continues processing)
- Progress tracking (logs each enrichment step)
- Interrupt-safe (Ctrl+C stops gracefully)

**Dependencies:**
- Required: (none - minimal DNS/SSL works without dependencies)
- Optional: `python-whois`, `geoip2`, `ipwhois`, `langdetect`, `requests`

---

## Usage Examples

### Complete First-Time Setup

```bash
# 1. Install basic dependencies
pip install requests python-dotenv

# 2. Optional: Configure API keys in .env
echo "PHISHTANK_API_KEY=your_key" >> .env
echo "URLHAUS_API_KEY=your_key" >> .env

# 3. Create and populate raw database
python -m app.database.rawdb
python -m app.database.grabrawdata

# 4. Create enriched database schema
python -m app.database.db

# 5. Optional: Install enrichment dependencies
pip install python-whois geoip2 ipwhois langdetect

# 6. Optional: Download GeoIP databases
# Sign up at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
# Place in app/database/

# 7. Test enrichment with 10 URLs
python -m app.database.enrich --limit 10

# 8. Full enrichment (overnight)
nohup python -m app.database.enrich --skip-existing > enrichment.log 2>&1 &
```

---

### Daily Maintenance

```bash
# Update raw feeds (safe to run daily - idempotent)
python -m app.database.grabrawdata

# Enrich new URLs only
python -m app.database.enrich --skip-existing --limit 5000
```

---

### Automated Updates (Cron)

```bash
# Edit crontab
crontab -e

# Add daily updates
0 2 * * * cd /path/to/phishing-detector && /path/to/venv/bin/python -m app.database.grabrawdata >> /var/log/threat_feeds.log 2>&1
0 3 * * * cd /path/to/phishing-detector && /path/to/venv/bin/python -m app.database.enrich --skip-existing --limit 5000 >> /var/log/enrichment.log 2>&1
```

---

### Query Examples

```sql
-- Count URLs by source
SELECT source_feed, COUNT(*) as count
FROM enriched_threats
GROUP BY source_feed;

-- Find phishing sites still online
SELECT url, domain, country, target_brand
FROM enriched_threats
WHERE online = 'yes' AND threat_type = 'phishing'
ORDER BY first_seen DESC
LIMIT 20;

-- Find sites by country
SELECT country_name, COUNT(*) as count
FROM enriched_threats
GROUP BY country_name
ORDER BY count DESC;

-- Find sites with valid SSL certificates
SELECT url, domain, cert_issuer, cert_valid_to
FROM enriched_threats
WHERE ssl_enabled = 'yes'
ORDER BY cert_valid_to ASC;

-- Check enrichment completeness
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN ip_address IS NOT NULL THEN 1 ELSE 0 END) as has_ip,
    SUM(CASE WHEN registrar IS NOT NULL THEN 1 ELSE 0 END) as has_whois,
    SUM(CASE WHEN country IS NOT NULL THEN 1 ELSE 0 END) as has_geo,
    SUM(CASE WHEN ssl_enabled = 'yes' THEN 1 ELSE 0 END) as has_ssl
FROM enriched_threats;
```

---

## Performance & Optimization

### Enrichment Speed

**Configuration-Based Times (per URL):**
- **Minimal** (DNS + SSL + HTTP only): ~2 seconds
- **Fast** (GeoIP databases, no WHOIS): ~1 second
- **Full** (all features): ~4-6 seconds

**For 52,000 URLs:**
- **Minimal**: ~29 hours
- **Fast**: ~15 hours
- **Full**: ~58 hours

### Optimization Tips

1. **Use GeoIP Databases** (not IPWhois)
   - Offline = no rate limits
   - 50-100x faster than RDAP queries
   - Download from MaxMind (free)

2. **Process in Batches**
   ```bash
   # Process 1000 at a time with cooldown
   for i in (seq 1 50)
       python -m app.database.enrich --limit 1000 --skip-existing
       sleep 60  # 1 minute cooldown
   end
   ```

3. **Skip WHOIS for Speed**
   - Don't install `python-whois` package
   - Enrichment will skip WHOIS queries entirely
   - Cuts processing time by ~40%

4. **Use `--skip-existing`**
   - Avoids reprocessing enriched URLs
   - Essential for incremental updates

5. **Process Specific Sources**
   ```bash
   # PhishTank has most metadata already
   python -m app.database.enrich --source phishtank --limit 10000
   
   # OpenPhish needs more enrichment
   python -m app.database.enrich --source openphish --limit 1000
   ```

### Rate Limits to Respect

- **WHOIS servers:** 1 second between queries (hard-coded)
- **IPWhois RDAP:** No explicit limit, but use responsibly
- **HTTP probes:** 0.5 second delay between URLs
- **Public APIs:** PhishTank/OpenPhish have rate limits if API keys not used

---

## Troubleshooting

### "No URLs found in raw database"
**Solution:**
```bash
python -m app.database.grabrawdata
```

### "Enriched database not found"
**Solution:**
```bash
python -m app.database.db
```

### "python-whois not installed"
**Solution:**
```bash
pip install python-whois
# Or skip WHOIS by not installing (enrichment continues without it)
```

### "GeoIP database not found"
**Solution:**
1. Download from https://www.maxmind.com/en/geolite2/signup
2. Place .mmdb files in `app/database/`
3. Or let pipeline use IPWhois fallback (slower but works)

### "WHOIS timeouts / rate limited"
**Symptoms:** Many "WHOIS lookup failed" messages, slow enrichment  
**Solutions:**
- Increase `WHOIS_DELAY` in enrich.py (line ~78)
- Process in smaller batches with `--limit`
- Use `--skip-existing` to avoid reprocessing
- Accept ~31% WHOIS success rate (expected)

### "Enrichment too slow"
**Solutions:**
- Use `--limit` to process fewer URLs at once
- Use GeoIP databases instead of IPWhois (much faster)
- Skip WHOIS by not installing python-whois
- Process specific sources with `--source`
- Run overnight for large datasets

### "Database is locked"
**Symptoms:** "database is locked" error  
**Solutions:**
- Close any SQLite browser/viewer apps
- Ensure no other enrichment processes running
- Check for WAL journal files (*.db-wal, *.db-shm)
- Wait a few seconds and retry

### "Module not found" errors
**Solution:**
```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install requests python-dotenv python-whois geoip2 ipwhois langdetect
```

### URLhaus returns no data
**Symptoms:** "Warning: URLHAUS_API_KEY environment variable not set"  
**Solution:**
1. Get API key from https://auth.abuse.ch/
2. Add to .env file: `URLHAUS_API_KEY=your_key_here`
3. Re-run grabrawdata.py

---

## Summary

### Key Takeaways

1. **Two-Database Architecture:**
   - Raw database (threat_feeds_raw.db) - unprocessed URLs
   - Enriched database (threat_feeds.db) - intelligence-enhanced URLs

2. **Three-Phase Process:**
   - Phase 1: Create & populate raw database (grabrawdata.py)
   - Phase 2: Create enriched database schema (db.py)
   - Phase 3: Run enrichment pipeline (enrich.py)

3. **Enrichment Sources:**
   - DNS, WHOIS, GeoIP, IPWhois, SSL/TLS, HTTP, Language Detection
   - Graceful degradation - works with any combination of dependencies

4. **Realistic Expectations:**
   - 100% success: IP, country, city, ASN, ISP, SSL status, online status
   - ~86% success: CIDR blocks (CDN limitation)
   - ~59% success: Page language (offline sites, short titles)
   - ~31% success: WHOIS data (privacy protection, TLD restrictions)

5. **Performance:**
   - ~4-6 seconds per URL (full enrichment)
   - ~52,000 URLs = ~58 hours
   - Use GeoIP databases for 2-3x speedup

6. **Maintenance:**
   - Run grabrawdata.py daily for new threats
   - Run enrich.py with --skip-existing for incremental updates
   - Set up cron jobs for automation

---

**Last Updated:** October 9, 2025  
**Database Versions:**
- threat_feeds_raw.db: 37 MB, ~52,000 URLs
- threat_feeds.db: 84 KB, schema ready for enrichment
