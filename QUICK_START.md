# 🚀 Quick Start Guide

## TL;DR - Just 2 Commands

```bash
# 1. First time? Run demo (auto-setup + test)
python run.py demo --once

# 2. Open dashboard to see results
python run.py dashboard
```

Done! 🎉

## The 4 Commands You Actually Need

### 1️⃣ `demo` - Everything Automated
```bash
python run.py demo
```
- Auto-setup database
- Auto-authenticate Gmail
- Fetch emails every 5 minutes
- Analyze for threats
- Show statistics

**Options:**
- `--once` - Run once and exit (for testing)
- `--interval 60` - Check every 60 seconds
- `--count 10` - Fetch 10 emails per check

### 2️⃣ `auth` - Gmail Authentication
```bash
python run.py auth
```
- Opens browser for Google OAuth
- Saves token.json
- Only needed once

### 3️⃣ `bootstrap` - Fetch & Analyze Emails
```bash
python run.py bootstrap
```
- Fetch 10 recent emails
- Extract URLs
- Check against threat feeds
- Calculate risk scores

**Options:**
- `--count 25` - Fetch 25 emails instead

### 4️⃣ `dashboard` - View Results
```bash
python run.py dashboard
```
- Opens at http://localhost:8501
- View email risk scores
- See which URLs are threats
- Drill down into details

## 📋 Simple Workflow

### First Time Setup
```bash
# Step 1: Run demo once to test everything
python run.py demo --once

# Step 2: Open dashboard to see results
python run.py dashboard
```

### Regular Use
```bash
# Terminal 1: Continuous monitoring
python run.py demo

# Terminal 2: Dashboard
python run.py dashboard
```

### Manual Mode
```bash
# 1. Authenticate (once)
python run.py auth

# 2. Fetch and analyze emails
python run.py bootstrap --count 20

# 3. View in dashboard
python run.py dashboard
```

## 🔍 What Each Command Shows

### `demo` Output:
```
🎬 Starting DEMO MODE
📋 Step 1: Checking setup...
   ✓ Database exists
📋 Step 2: Gmail authenticated
📋 Step 3: Starting monitoring

📧 Iteration 1
Processing 3 extracted URLs...
  ✓ FOUND in threat feed: PhishTank
  🚨 Email marked as CRITICAL RISK (score: 100)

📊 Current Statistics:
   Total emails: 115
   Critical risk: 2
   High risk: 35

⏱️  Waiting 300 seconds...
```

### `bootstrap` Output:
```
✅ Fetched 10 messages: 2 new, 8 already existed

Enriching 2 newly fetched emails...
Processing 5 extracted URLs...
  ✓ Enriched and linked: https://example.com (risk_score: 42)

📊 Email Risk Assessment:
   ✓ Email xyz marked as LOW RISK (score: 42)
```

### `dashboard` Output:
Opens browser with:
- **Email Monitoring Tab** (first tab)
- Critical/High/Medium/Low risk counts
- Email list with risk scores
- Drill-down into URLs and threat details

## ❓ FAQ

**Q: Do I need to run setup manually?**  
A: No! `demo` does it automatically.

**Q: How do I stop continuous monitoring?**  
A: Press `Ctrl+C`

**Q: How do I check just once without continuous loop?**  
A: `python run.py demo --once`

**Q: Can I check emails more frequently?**  
A: `python run.py demo --interval 60` (every minute)

**Q: How do I re-analyze old emails?**  
A: They're automatically skipped. Use the dashboard to view them.

**Q: What if I don't see any emails?**  
A: Run `python debug_emails.py --check` to diagnose.

## 🎯 Choose Your Style

| If you want... | Use this |
|----------------|----------|
| Easiest setup | `python run.py demo --once` |
| Continuous monitoring | `python run.py demo` |
| Manual control | `python run.py auth` then `python run.py bootstrap` |
| Just view existing data | `python run.py dashboard` |
| Quick test | `python run.py demo --once --count 3` |

## 🚫 What NOT to Use

These are advanced/internal commands - **you probably don't need them**:
- `fetch` - Downloads threat feeds (demo does this)
- `enrich` - Processes threat data (demo does this)
- `db` - Creates database (demo does this)
- `emails` - Fetches without analyzing (use bootstrap instead)
- `enrich-emails` - Analyzes without fetching (use bootstrap instead)
- `api` - Runs REST API (use dashboard instead)

## 💡 Pro Tips

1. **Always start with**: `python run.py demo --once`
2. **View results in**: `python run.py dashboard`
3. **For production**: `python run.py demo` (continuous)
4. **To debug**: `python debug_emails.py --check`

That's it! Just 4 commands for everything. 🎯

