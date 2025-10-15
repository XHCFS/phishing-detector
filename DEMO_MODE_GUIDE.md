# 🎬 Demo Mode Guide

## Quick Start

The easiest way to get started with the phishing detector:

```bash
python run.py demo
```

That's it! This single command will:
1. ✅ Check if database exists (run setup if needed)
2. ✅ Download threat feeds
3. ✅ Enrich data
4. ✅ Authenticate Gmail (if needed)
5. ✅ Start continuous email monitoring

## What Demo Mode Does

### Auto-Setup
- Creates database schema
- Fetches threat feeds (OpenPhish, PhishTank, URLhaus)
- Enriches 500 URLs for quick start
- Authenticates Gmail OAuth

### Continuous Monitoring
- Fetches 5 emails every 5 minutes (configurable)
- Enriches URLs from emails
- Checks against threat feeds
- Calculates risk scores
- Shows statistics after each iteration

## Usage

### Basic Demo
```bash
python run.py demo
```

### Single Run (No Loop)
```bash
python run.py demo --once
```

### Custom Fetch Interval
```bash
# Check every 60 seconds
python run.py demo --interval 60

# Check every 10 minutes
python run.py demo --interval 600
```

### Custom Email Count
```bash
# Fetch 10 emails per iteration
python run.py demo --count 10
```

### Force Re-setup
```bash
# Re-run setup even if database exists
python run.py demo --force-setup
```

### Skip Certain Feeds
```bash
# Skip slow feeds for faster setup
python run.py demo --skip-urlhaus --skip-openphish
```

## Example Output

```
🎬 Starting DEMO MODE
======================================================================

📋 Step 1: Checking setup...
   ✓ Database exists, skipping setup
   (Use --force-setup to re-run setup)

📋 Step 2: Checking Gmail authentication...
   ✓ Gmail already authenticated

📋 Step 3: Starting continuous email monitoring
   Fetch interval: 300 seconds
   Emails per fetch: 5
   Press Ctrl+C to stop

======================================================================

======================================================================
📧 Iteration 1 - 2025-10-15 14:30:00
======================================================================

🚀 Bootstrapping email processing...
Fetched and stored 5 messages

Processing 3 extracted URLs...

  Processing: https://malicious-site.com/login
    ✓ FOUND in threat feed: PhishTank
    → Setting risk_score = 100 (external threat)

  Processing: https://suspicious.zip/verify
    → New URL, enriching...
    ✓ Enriched and linked: https://suspicious.zip/verify (risk_score: 95)

  Processing: https://legitimate.com
    → New URL, enriching...
    ✓ Enriched and linked: https://legitimate.com (risk_score: 42)

📊 Email Risk Assessment:
   Processed 3 URLs
   URL Risk Scores: [100, 95, 42]
   Maximum Risk Score: 100
   🚨 Email abc123 marked as CRITICAL RISK

✅ Email bootstrap complete

📊 Current Statistics:
   Total emails: 15
   Critical risk: 3
   High risk: 2

⏱️  Waiting 300 seconds until next fetch...
   (Press Ctrl+C to stop)
```

## Alternative Commands

### If You Don't Want Demo Mode

**Fetch emails only (no enrichment):**
```bash
python run.py emails --count 10
```

**Fetch AND enrich:**
```bash
python run.py emails --count 10 --enrich
```

**One-shot fetch + enrich:**
```bash
python run.py bootstrap --count 10
```

**Manual enrichment:**
```bash
python run.py enrich-emails
```

## Stopping Demo Mode

Press `Ctrl+C` to stop gracefully:

```
^C
⏹️  Demo mode stopped by user
   Completed 5 iterations
```

## Pro Tips

1. **Start with --once** to test without continuous loop:
   ```bash
   python run.py demo --once
   ```

2. **Use shorter intervals for testing**:
   ```bash
   python run.py demo --interval 30 --count 3
   ```

3. **Check stats at any time**:
   ```bash
   sqlite3 app/database/threat_feeds.db \
     "SELECT COUNT(*), AVG(risk_score) FROM emails"
   ```

4. **View high-risk emails**:
   ```bash
   sqlite3 app/database/threat_feeds.db \
     "SELECT sender, subject, risk_score FROM emails WHERE risk_score >= 85"
   ```

## What's Different from Before?

### Old Way (Manual)
```bash
# Setup
./setup.sh

# Authenticate
python -m app.detector.core --authenticate

# Fetch emails
python -m app.detector.core --fetch 10

# Enrich emails
python -m app.detector.core --enrich-all

# Repeat manually...
```

### New Way (Automated)
```bash
# Everything in one command
python run.py demo
```

## Troubleshooting

### "Virtual environment not found"
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### "Gmail authentication failed"
Make sure you have `app/detector/credentials.json` with your OAuth credentials.

### "Database check failed"
```bash
python run.py demo --force-setup
```

### Demo runs but doesn't find any emails
Check your Gmail inbox has emails, or adjust the count:
```bash
python run.py demo --count 50
```

