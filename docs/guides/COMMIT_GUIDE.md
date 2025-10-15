# 📦 Commit Guide

## Files to Commit

### ✅ Core System Files (REQUIRED)
```bash
git add app/database/db.py
git add app/database/enrich.py  
git add app/detector/core.py
git add app/detector/scoring.py
git add app/dashboard/frontend.py
git add run.py
git add .gitignore
```

### ✅ User Interface (REQUIRED)
```bash
git add start.py
```

### ✅ Documentation (REQUIRED)
```bash
git add README.md
git add QUICK_START.md
git add EMAIL_DASHBOARD_GUIDE.md
git add DEMO_MODE_GUIDE.md
git add DOCUMENTATION_MAP.md
git add docs/README.md
```

### 🔧 Debug Utilities (OPTIONAL)
```bash
git add check_duplicates.py
git add check_url_matching.py
git add debug_emails.py
```

---

## 🚀 Quick Commit Commands

### Recommended (Everything except utils):
```bash
git add app/database/db.py app/database/enrich.py app/detector/core.py app/detector/scoring.py app/dashboard/frontend.py run.py .gitignore start.py README.md QUICK_START.md EMAIL_DASHBOARD_GUIDE.md DEMO_MODE_GUIDE.md DOCUMENTATION_MAP.md docs/
```

### All Files:
```bash
git add app/ run.py .gitignore start.py *.md docs/ check*.py debug*.py
```

---

## 📝 Suggested Commit Message

```
feat: unified email threat detection with auto-dashboard and risk scoring

Major Features:
- Email threat detection with automatic risk scoring (0-100)
- Unified threat_feeds.db (emails, email_urls, enriched_threats)
- Async URL enrichment for 5-10x speed improvement
- Auto-launching dashboard in demo mode with live refresh
- URL normalization for accurate threat matching

Dashboard:
- New Email Monitoring tab as primary interface
- Auto-refresh every 10s in demo mode
- Color-coded risk levels (Critical/High/Medium/Low)
- Detailed drill-down: email → URLs → full enrichment data
- Threat feed URL highlighting (🚨 THREAT FEED badge)

User Experience:
- One-command demo mode: `python run.py demo`
- Interactive menu: `python start.py`
- Simplified CLI with clear help text
- Comprehensive linked documentation structure

Bug Fixes:
- Fixed INSERT OR REPLACE overwriting threat feed data
- Fixed datetime timezone comparison errors
- Prevented duplicate URL enrichment
- Fixed Streamlit deprecation warnings

Documentation:
- Created unified documentation structure with cross-linking
- Added QUICK_START.md (4 essential commands)
- Added EMAIL_DASHBOARD_GUIDE.md (dashboard features)
- Added DEMO_MODE_GUIDE.md (continuous monitoring)
- Added docs/README.md (master documentation index)
- Added DOCUMENTATION_MAP.md (navigation structure)

Breaking Changes:
- emails.db removed (all data now in threat_feeds.db)
- email_urls schema simplified (email_id, url_id junction table)
```

---

## 📊 What Changed

### Database Schema
- `enriched_threats` table: Added `risk_score` column
- `emails` table: Added with `risk_score` column
- `email_urls` table: Simple junction table (email_id, url_id)
- All tables unified in `threat_feeds.db`

### Core Logic
- URL normalization for consistent matching
- Async enrichment with parallel processing
- Automatic risk score calculation
- Duplicate enrichment prevention
- Threat feed protection (INSERT OR IGNORE)

### User Interface
- Demo mode auto-launches dashboard
- Dashboard auto-refreshes in demo mode
- Interactive menu (start.py)
- Simplified run.py with clear sections
- Comprehensive documentation linking

---

## ✅ Pre-Commit Checklist

- [ ] All core files added
- [ ] Documentation files added
- [ ] .gitignore updated
- [ ] No sensitive data (credentials.json, token.json, *.db)
- [ ] Commit message describes changes
- [ ] Ready to push

---

## 🧪 Post-Commit Testing

After committing, verify with:

```bash
# Clone fresh copy
git clone <repo> test-phishing-detector
cd test-phishing-detector

# Test one-command setup
python run.py demo --once

# Should see:
# ✓ Database setup
# ✓ Gmail auth
# ✓ Dashboard opens
# ✓ Emails fetched and analyzed
# ✓ Risk scores displayed
```

---

## 📚 Documentation Structure

All documentation now follows this pattern:

```
[Document Header]
    ↓
[Main Content]
    ↓
[Navigation Footer]
    ├── ← Back to previous level
    ├── → Related docs (same level)
    └── → Master index (docs/README.md)
```

**No document is isolated!** Every MD file has:
- Clear navigation links at the bottom
- Links to related documentation
- Path back to main README
- Link to master index

---

**Ready to commit!** 🚀

