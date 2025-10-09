# Threat Feeds Database System

Complete database system for collecting and enriching phishing/malware threat intelligence.

## Quick Start

### Prerequisites
```bash
# Basic dependencies
pip install requests python-dotenv

# Optional: For full enrichment capabilities
pip install python-whois geoip2 ipwhois langdetect
```

### Setup (5 minutes)

**1. Create Raw Database**
```bash
python -m app.database.rawdb
```

**2. Populate with Threat Feeds**
```bash
python -m app.database.grabrawdata
```

**3. Create Enriched Database**
```bash
python -m app.database.db
```

**4. Run Enrichment (test with 10 URLs)**
```bash
python -m app.database.enrich --limit 10
```

That's it! Your database system is ready.

---

## System Overview

### Two-Database Architecture

```
Public Feeds → threat_feeds_raw.db → Enrichment → threat_feeds.db
```

**Raw Database** (`threat_feeds_raw.db` - 37 MB)
- OpenPhish: ~600 URLs
- PhishTank: ~51,000 URLs  
- URLhaus: ~800 URLs
- **Total:** ~52,000 threat URLs

**Enriched Database** (`threat_feeds.db` - grows as enriched)
- 41 fields per URL including:
  - Network: IP, ASN, ISP, CIDR
  - Location: Country, City, GPS coordinates
  - SSL: Certificates, validity dates
  - WHOIS: Registrar, registration dates
  - Status: Online status, HTTP codes

---

## Detailed Setup Steps

### Step 1: Raw Database

#### 1.1 Create Schema
```bash
python -m app.database.rawdb
```
Creates `threat_feeds_raw.db` with 3 tables.

#### 1.2 Optional: Configure API Keys

Create `.env` file in project root:
```bash
# Optional - for higher PhishTank rate limits
PHISHTANK_API_KEY=your_key_here

# Required for URLhaus data
URLHAUS_API_KEY=your_key_here
```

**Get API Keys:**
- PhishTank: https://phishtank.org/api_register.php (optional)
- URLhaus: https://auth.abuse.ch/ (required for URLhaus data)

#### 1.3 Populate Database
```bash
# Fetch all feeds
python -m app.database.grabrawdata

# Or skip specific feeds
python -m app.database.grabrawdata --skip-urlhaus
```

**Verify:**
```bash
sqlite3 app/database/threat_feeds_raw.db "
  SELECT 'OpenPhish' as source, COUNT(*) FROM openphish_feed 
  UNION ALL 
  SELECT 'PhishTank', COUNT(*) FROM phishtank_archival 
  UNION ALL 
  SELECT 'URLhaus', COUNT(*) FROM urlhaus_api;"
```

---

### Step 2: Enriched Database

#### 2.1 Create Schema
```bash
python -m app.database.db
```
Creates `threat_feeds.db` with `enriched_threats` table (41 fields).

**Verify:**
```bash
sqlite3 app/database/threat_feeds.db ".schema enriched_threats"
```

---

### Step 3: Enrichment

#### 3.1 Optional: Install Full Dependencies
```bash
# Minimal enrichment (DNS + SSL + HTTP + GeoIP)
# No additional packages needed

# Full enrichment (recommended)
pip install python-whois geoip2 ipwhois langdetect aiohttp
```

#### 3.2 Optional: Download GeoIP Databases (Fast Lookups)
1. Sign up: https://www.maxmind.com/en/geolite2/signup
2. Download: `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`
3. Place in: `app/database/`

**Benefits:**
- 50-100x faster than online lookups
- No rate limits
- Offline operation

#### 3.3 Run Enrichment

**Performance Modes:**

```bash
# MAXIMUM SPEED MODE (~20-30 sec for 300 URLs)
# Skips: WHOIS, IPWhois, Page content
python -m app.database.enrich --limit 300 \
  --disable-whois --disable-ipwhois --disable-page-content

# FAST MODE (~30-40 sec for 300 URLs)
# Skips: Page content (slowest operation)
python -m app.database.enrich --limit 300 --disable-page-content

# BALANCED MODE (~40-50 sec for 300 URLs)
# Skips: WHOIS (registrar data), IPWhois (CIDR blocks)
python -m app.database.enrich --limit 300 \
  --disable-whois --disable-ipwhois

# FULL MODE - Default (~60-90 sec for 300 URLs)
# Collects everything: WHOIS, IPWhois, page content
python -m app.database.enrich --limit 300
```

**Production (all URLs):**
```bash
# Fast mode for large batches (recommended)
python -m app.database.enrich --skip-existing \
  --disable-page-content --concurrency 100 --workers 200

# Full enrichment (overnight job for all data)
nohup python -m app.database.enrich --skip-existing > enrichment.log 2>&1 &
```

**Monitor Progress:**
```bash
# Watch log
tail -f enrichment.log

# Check enriched count
sqlite3 app/database/threat_feeds.db "SELECT COUNT(*) FROM enriched_threats;"
```

---

## Usage Examples

### Query Enriched Data

```sql
-- View sample enriched URLs
SELECT url, domain, country, city, ssl_enabled, online 
FROM enriched_threats 
LIMIT 5;

-- Count by country
SELECT country_name, COUNT(*) as count
FROM enriched_threats
GROUP BY country_name
ORDER BY count DESC;

-- Find active phishing sites
SELECT url, domain, target_brand, country
FROM enriched_threats
WHERE online = 'yes' AND threat_type = 'phishing'
ORDER BY first_seen DESC;

-- Check enrichment completeness
SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN ip_address IS NOT NULL THEN 1 ELSE 0 END) as has_ip,
    SUM(CASE WHEN country IS NOT NULL THEN 1 ELSE 0 END) as has_geo,
    SUM(CASE WHEN registrar IS NOT NULL THEN 1 ELSE 0 END) as has_whois
FROM enriched_threats;
```

### Daily Updates

```bash
# Update raw feeds (safe to run daily - idempotent)
python -m app.database.grabrawdata

# Fast enrichment of new URLs (recommended for daily updates)
python -m app.database.enrich --skip-existing --limit 5000 \
  --disable-page-content --concurrency 100
```

### Automated Updates (Cron)

```bash
# Edit crontab
crontab -e

# Add daily updates at 2 AM (fast mode for quick updates)
0 2 * * * cd /path/to/phishing-detector && /path/to/venv/bin/python -m app.database.grabrawdata >> /var/log/threat_feeds.log 2>&1
0 3 * * * cd /path/to/phishing-detector && /path/to/venv/bin/python -m app.database.enrich --skip-existing --limit 5000 --disable-page-content --concurrency 100 >> /var/log/enrichment.log 2>&1
```

---

## Command Reference

### grabrawdata.py (Populate Raw Database)
```bash
# Basic usage
python -m app.database.grabrawdata

# Skip specific feeds
python -m app.database.grabrawdata --skip-openphish
python -m app.database.grabrawdata --skip-phishtank
python -m app.database.grabrawdata --skip-urlhaus

# Custom database path
python -m app.database.grabrawdata --db /path/to/custom.db
```

### enrich.py (Enrichment Pipeline)

**Basic Usage:**
```bash
# Test with 10 URLs (full mode)
python -m app.database.enrich --limit 10

# Process specific source
python -m app.database.enrich --source phishtank --limit 500
python -m app.database.enrich --source openphish
python -m app.database.enrich --source urlhaus
```

**Performance Presets:**
```bash
# Maximum speed (skip slow operations)
python -m app.database.enrich --limit 1000 --skip-existing \
  --disable-whois --disable-ipwhois --disable-page-content

# Fast (skip page content only)
python -m app.database.enrich --limit 1000 --skip-existing \
  --disable-page-content

# Balanced (skip WHOIS/IPWhois)
python -m app.database.enrich --limit 1000 --skip-existing \
  --disable-whois --disable-ipwhois

# Full enrichment (default - all data)
python -m app.database.enrich --limit 1000 --skip-existing
```

**Advanced Options:**
```bash
# Custom concurrency (default: 100 URLs, 200 workers)
python -m app.database.enrich --concurrency 150 --workers 250

# Custom database paths
python -m app.database.enrich \
  --raw-db /path/to/raw.db \
  --enriched-db /path/to/enriched.db

# Legacy synchronous mode (for debugging)
python -m app.database.enrich --legacy --limit 10
```

**All Flags:**
- `--limit N` - Process only N URLs
- `--skip-existing` - Skip already enriched URLs
- `--source {openphish,phishtank,urlhaus}` - Process specific feed
- `--disable-whois` - Skip WHOIS lookups (faster, loses registrar data)
- `--disable-ipwhois` - Skip IPWhois lookups (faster, loses CIDR data)
- `--disable-page-content` - Skip page fetching (faster, loses title/lang)
- `--concurrency N` - URLs per batch (default: 100)
- `--workers N` - Thread pool size (default: 200)
- `--legacy` - Use synchronous processing (slower, for debugging)

---

## File Structure

```
app/database/
├── README.md                    # This file
├── rawdb.py                     # Create raw database schema
├── grabrawdata.py               # Populate raw database from feeds
├── db.py                        # Create enriched database schema
├── enrich.py                    # Enrichment pipeline (main)
├── threat_feeds_raw.db          # Raw threat data (37 MB)
├── threat_feeds.db              # Enriched threat data (grows)
└── Documentation & Sources Research/
    ├── DATABASE_GUIDE.md        # Complete documentation (985 lines)
    └── Data Sources.md          # Threat feed source details
```

---

## Enrichment Data Sources

The enrichment pipeline collects data from multiple sources:

| Source | Speed | Data Provided | Dependency | Can Disable |
|--------|-------|---------------|------------|-------------|
| **DNS** | Fast | IP addresses | Built-in | Always on |
| **SSL/TLS** | Medium | Certificates, validity | Built-in | Always on |
| **HTTP** | Fast | Online status | `requests` / `aiohttp` | Always on |
| **GeoIP** | Very Fast | Country, city, GPS, ASN | `geoip2` + databases | Always on |
| **WHOIS** | Slow | Registrar, dates, nameservers | `python-whois` | `--disable-whois` |
| **IPWhois** | Slow | CIDR blocks (detailed) | `ipwhois` | `--disable-ipwhois` |
| **Page Content** | Very Slow | Page title, language | `requests` + `langdetect` | `--disable-page-content` |

**Performance Impact:**
- **DNS, SSL, HTTP, GeoIP**: Fast core operations (~0.3-1s per URL)
- **WHOIS, IPWhois**: Slower but valuable (~1-2s per URL)
- **Page Content**: Slowest operation (~2-4s per URL) - **disable for speed**

**Graceful Degradation:** The pipeline works with any combination of dependencies. More dependencies = more enriched data.

---

## Performance

### Enrichment Speed Modes

| Mode | Speed (300 URLs) | What's Collected | What's Skipped |
|------|------------------|------------------|----------------|
| **Maximum Speed** | 15-25 sec | DNS, GeoIP, SSL, online status | WHOIS, IPWhois, page content |
| **Fast** | 30-40 sec | + WHOIS, IPWhois | Page content |
| **Balanced** | 40-50 sec | + Page content | WHOIS, IPWhois |
| **Full** (default) | 60-90 sec | Everything | Nothing |

**Commands:**
```bash
# Maximum speed
--disable-whois --disable-ipwhois --disable-page-content

# Fast mode
--disable-page-content

# Balanced
--disable-whois --disable-ipwhois

# Full mode (default)
# No flags needed
```

### For 52,000 URLs (Full Dataset)

| Mode | Estimated Time | URLs/sec |
|------|---------------|----------|
| Maximum Speed | ~6-9 hours | 1.6-2.4 |
| Fast | ~12-15 hours | 1.0-1.2 |
| Balanced | ~15-18 hours | 0.8-1.0 |
| Full | ~24-36 hours | 0.4-0.6 |

### Optimization Tips
1. **Use GeoIP databases** - 50-100x faster than IP-API
2. **Disable page content** (biggest speedup) - saves 2-3s per URL
3. **Process in batches** with `--limit 1000 --skip-existing`
4. **High concurrency** - `--concurrency 100 --workers 200`
5. **Skip WHOIS/IPWhois** for speed - use `--disable-whois --disable-ipwhois`
6. **Install aiohttp** - `pip install aiohttp` for async HTTP (faster)
7. **Process overnight** for full enrichment of large datasets

---

## Enrichment Limitations

### Fields with 100% Success
- IP address, country, city, ASN, ISP
- SSL status, online status
- Domain, TLD

### Fields with Partial Success
- **CIDR blocks** (~86%) - CDNs don't expose ranges
- **Page language** (~59%) - Requires online site
- **Page title** (~97%) - Requires HTTP response

### Fields with Low Success
- **WHOIS data** (~31%) - Privacy protection, TLD restrictions
  - **Why:** WHOIS privacy services, subdomain hosting, rate limits
  - **Cannot fix:** Fundamental protocol/policy limitations
- **SSL certificates** (HTTPS only) - HTTP sites have NULL (correct)
- **Target brand** (PhishTank only) - Other feeds don't include it

**See [DATABASE_GUIDE.md](Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md#enrichment-limitations) for detailed explanations.**

---

## Troubleshooting

### "No URLs found in raw database"
```bash
python -m app.database.grabrawdata
```

### "Enriched database not found"
```bash
python -m app.database.db
```

### "python-whois not installed"
```bash
pip install python-whois
# Or skip WHOIS - enrichment continues without it
```

### "GeoIP database not found"
1. Download from https://www.maxmind.com/en/geolite2/signup
2. Place `.mmdb` files in `app/database/`
3. Or let pipeline use IPWhois fallback (slower but works)

### "Database is locked"
- Close SQLite browser/viewer applications
- Ensure no other enrichment processes running
- Check for WAL files (`*.db-wal`, `*.db-shm`)

### "Enrichment too slow"
- Use `--limit` to process fewer URLs
- Install GeoIP databases (50-100x faster)
- Skip WHOIS (don't install `python-whois`)
- Process specific sources with `--source`

---

## Documentation

**Complete Guide:** [DATABASE_GUIDE.md](Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md) (985 lines)
- Detailed architecture and data flow
- Complete enrichment data source explanations
- Technical limitations and why they exist
- Performance optimization strategies
- Comprehensive troubleshooting

**Data Sources:** [Data Sources.md](Documentation%20%26%20Sources%20Research/Data%20Sources.md)
- OpenPhish, PhishTank, URLhaus details
- API specifications and examples
- Additional sources (Google Safe Browsing, dnstwist, etc.)

---

## Support

For detailed information, see:
- **Setup Issues:** This README
- **Technical Details:** [DATABASE_GUIDE.md](Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md)
- **Data Sources:** [Data Sources.md](Documentation%20%26%20Sources%20Research/Data%20Sources.md)

---

## Summary

**3-Step Setup:**
1. `python -m app.database.rawdb` - Create raw DB
2. `python -m app.database.grabrawdata` - Populate raw DB
3. `python -m app.database.db` - Create enriched DB
4. `python -m app.database.enrich --limit 10` - Test enrichment

**Daily Maintenance (Fast Mode):**
```bash
python -m app.database.grabrawdata  # Update feeds
python -m app.database.enrich --skip-existing --limit 5000 \
  --disable-page-content --concurrency 100  # Fast enrichment
```

**Performance Modes:**
- **Maximum Speed**: Add `--disable-whois --disable-ipwhois --disable-page-content`
- **Fast**: Add `--disable-page-content`
- **Balanced**: Add `--disable-whois --disable-ipwhois`
- **Full** (default): No flags needed

**Database Status:**
- Raw: ~52,000 URLs from 3 public feeds
- Enriched: 41 fields per URL (network, geo, SSL, WHOIS, status)

Ready to detect phishing!
