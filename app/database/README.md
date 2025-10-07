# Threat Feeds Database Setup

This directory contains scripts to populate a threat intelligence database from public feeds.

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Keys
Copy the example environment file and add your API keys:
```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

#### URLhaus API Key (Required)
- Get a free API key from: https://auth.abuse.ch/
- Add it to `.env`: `URLHAUS_API_KEY=your_key_here`
- Without this key, URLhaus data will be skipped

#### PhishTank API Key (Optional)
- Get from: https://phishtank.org/api_register.php  
- Add it to `.env`: `PHISHTANK_API_KEY=your_key_here`
- Without this, you'll use the public endpoint with lower rate limits

### 3. Run the Script
```bash
# Full update (all sources)
python grabrawdata.py --db threat_feeds_raw.db

# Skip specific sources
python grabrawdata.py --db threat_feeds_raw.db --skip-openphish
python grabrawdata.py --db threat_feeds_raw.db --skip-phishtank
python grabrawdata.py --db threat_feeds_raw.db --skip-urlhaus
```

## Data Sources

- **OpenPhish**: Free phishing URL feed (no API key required)
- **PhishTank**: Verified phishing URLs (API key optional for higher limits)
- **URLhaus**: Malware distribution URLs (API key required)

## Database Schema

The script creates three main tables:
- `openphish_feed`: OpenPhish URLs with domains
- `phishtank_archival`: PhishTank verified phishing URLs
- `urlhaus_api`: URLhaus malware distribution URLs

## Verification

Check your data import:
```bash
# View record counts
sqlite3 threat_feeds_raw.db "SELECT 'OpenPhish' as source, COUNT(*) as count FROM openphish_feed UNION ALL SELECT 'PhishTank' as source, COUNT(*) as count FROM phishtank_archival UNION ALL SELECT 'URLhaus' as source, COUNT(*) as count FROM urlhaus_api;"

# Check database size
ls -lh threat_feeds_raw.db
```