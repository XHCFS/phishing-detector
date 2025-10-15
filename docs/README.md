# 📚 Documentation Index

**Complete documentation for the Phishing Email Detector system.**

---

## 🚀 Getting Started

| Document | Purpose | Audience |
|----------|---------|----------|
| **[Quick Start Guide](../QUICK_START.md)** | Get up and running in 2 minutes | Everyone |
| **[Main README](../README.md)** | Project overview and setup | Everyone |

**Start here:** [QUICK_START.md](../QUICK_START.md) - Just 4 commands to know!

---

## 📧 Email Monitoring (Primary Feature)

| Document | Purpose |
|----------|---------|
| **[Email Dashboard Guide](guides/EMAIL_DASHBOARD_GUIDE.md)** | Using the Email Monitoring interface |
| **[Demo Mode Guide](guides/DEMO_MODE_GUIDE.md)** | Automated setup and continuous monitoring |
| **[Detector Module](../app/detector/README.md)** | Email analysis technical details |

**For daily use:** [EMAIL_DASHBOARD_GUIDE.md](guides/EMAIL_DASHBOARD_GUIDE.md)

---

## 🗄️ Database & Threat Intelligence

| Document | Purpose |
|----------|---------|
| **[Database Quick Start](../app/database/README.md)** | Database setup and basic commands |
| **[Complete Database Guide](../app/database/Documentation%20&%20Sources%20Research/DATABASE_GUIDE.md)** | Full technical documentation (900+ lines) |
| **[Data Sources](../app/database/Documentation%20&%20Sources%20Research/Data%20Sources.md)** | Threat feed specifications |

**For setup:** [Database README](../app/database/README.md)  
**For details:** [DATABASE_GUIDE.md](../app/database/Documentation%20&%20Sources%20Research/DATABASE_GUIDE.md)

---

## 📊 Dashboard & Visualization

| Document | Purpose |
|----------|---------|
| **[Dashboard Quick Start](../app/dashboard/README.md)** | Launch and use dashboard |
| **[Dashboard Technical Guide](../app/dashboard/Documentation/DASHBOARD_GUIDE.md)** | Complete dashboard documentation |
| **[Email Dashboard Guide](../EMAIL_DASHBOARD_GUIDE.md)** | Email Monitoring tab features |

**For usage:** [Email Dashboard Guide](../EMAIL_DASHBOARD_GUIDE.md)  
**For customization:** [Dashboard Technical Guide](../app/dashboard/Documentation/DASHBOARD_GUIDE.md)

---

## 🛠️ Technical Documentation

| Document | Purpose | Lines |
|----------|---------|-------|
| **[Technical Report](../TECHNICAL_REPORT.md)** | Complete system design and evaluation | 1000+ |
| **[Detector Technical Guide](../app/detector/Documentation/DETECTOR_GUIDE.md)** | Email analysis architecture | 500+ |
| **[Database Technical Guide](../app/database/Documentation%20&%20Sources%20Research/DATABASE_GUIDE.md)** | Database schema and enrichment | 900+ |
| **[Dashboard Technical Guide](../app/dashboard/Documentation/DASHBOARD_GUIDE.md)** | Dashboard architecture | 850+ |

**For understanding the system:** [TECHNICAL_REPORT.md](../TECHNICAL_REPORT.md)

---

## 🔧 Utilities & Debugging

| Tool | Purpose | Command |
|------|---------|---------|
| **check_duplicates.py** | Check for database issues | `python check_duplicates.py` |
| **check_url_matching.py** | Test URL threat matching | `python check_url_matching.py URL` |
| **debug_emails.py** | Diagnose email database | `python debug_emails.py --check` |
| **start.py** | Interactive menu | `python start.py` |

---

## 📖 Documentation by Use Case

### I want to...

**Get started quickly**
→ [QUICK_START.md](../QUICK_START.md)

**Set up the database**
→ [Database README](../app/database/README.md)

**Monitor emails for threats**
→ [Email Dashboard Guide](guides/EMAIL_DASHBOARD_GUIDE.md)

**Run continuous monitoring**
→ [Demo Mode Guide](guides/DEMO_MODE_GUIDE.md)

**Understand the system architecture**
→ [Technical Report](technical/TECHNICAL_REPORT.md)

**Customize the dashboard**
→ [Dashboard Technical Guide](../app/dashboard/Documentation/DASHBOARD_GUIDE.md)

**Debug issues**
→ Use debug utilities above or check module READMEs

**Contribute to the project**
→ [Main README - Contributing](../README.md#contributing)

---

## 🗂️ Documentation Structure

```
phishing-detector/
├── 📄 README.md                    ← Start here (project overview)
├── 📄 QUICK_START.md               ← Quick start (4 commands)
│
├── 📧 Email Monitoring Docs
│   ├── EMAIL_DASHBOARD_GUIDE.md    ← Using the Email Monitoring tab
│   └── DEMO_MODE_GUIDE.md          ← Automated monitoring
│
├── 🗄️ Database Docs
│   └── app/database/
│       ├── README.md               ← Database quick start
│       └── Documentation & Sources Research/
│           ├── DATABASE_GUIDE.md   ← Complete database docs
│           └── Data Sources.md     ← Threat feed details
│
├── 📊 Dashboard Docs
│   └── app/dashboard/
│       ├── README.md               ← Dashboard quick start
│       └── Documentation/
│           └── DASHBOARD_GUIDE.md  ← Complete dashboard docs
│
├── 🔍 Detector Docs
│   └── app/detector/
│       ├── README.md               ← Detector quick start
│       └── Documentation/
│           └── DETECTOR_GUIDE.md   ← Complete detector docs
│
└── 📚 Technical Docs
    ├── TECHNICAL_REPORT.md         ← System design & evaluation
    ├── app/README.md               ← Module integration
    └── docs/README.md              ← This index
```

---

## 🎯 Quick Reference

### Commands
```bash
# One-line start
python run.py demo --once

# View results
python run.py dashboard

# Continuous monitoring  
python run.py demo

# Authenticate Gmail
python run.py auth

# Analyze emails
python run.py bootstrap
```

See [QUICK_START.md](../QUICK_START.md) for details.

### Help
```bash
python run.py --help              # All commands
python run.py demo --help         # Demo options
python start.py                   # Interactive menu
```

---

## 📝 Documentation Updates

Last updated: October 2025

**Recent additions:**
- Email Monitoring dashboard tab
- Demo mode with auto-dashboard
- Risk scoring documentation
- Interactive menu (start.py)
- Consolidated documentation structure

---

---

## 🗺️ Documentation Map

See **[DOCUMENTATION_MAP.md](../DOCUMENTATION_MAP.md)** for the complete navigation structure showing how all documentation files link together.

---

**Navigate:** [↑ Main README](../README.md) | [→ Quick Start](../QUICK_START.md) | [→ Email Monitoring](guides/EMAIL_DASHBOARD_GUIDE.md) | [→ Doc Map](guides/DOCUMENTATION_MAP.md)

