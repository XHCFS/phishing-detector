# 📁 File Organization

**Clean, organized directory structure for the phishing detector project.**

---

## 🎯 Root Directory (Clean!)

```
phishing-detector/
├── README.md                      ← Main entry point
├── QUICK_START.md                 ← Getting started (keep in root for visibility)
├── LICENSE                        ← Project license
│
├── start.py                       ← Interactive menu (primary user interface)
├── run.py                         ← Command runner (main CLI)
│
├── setup.sh, run.sh, etc.         ← Shell scripts
├── requirements.txt               ← Python dependencies
│
├── 📚 docs/                        ← All documentation
│   ├── README.md                  ← Documentation index
│   ├── guides/                    ← User guides
│   │   ├── EMAIL_DASHBOARD_GUIDE.md
│   │   ├── DEMO_MODE_GUIDE.md
│   │   ├── DOCUMENTATION_MAP.md
│   │   └── COMMIT_GUIDE.md
│   └── technical/                 ← Technical documentation
│       └── TECHNICAL_REPORT.md
│
├── 🔧 utils/                       ← Utility scripts
│   ├── check_duplicates.py
│   ├── check_url_matching.py
│   ├── debug_emails.py
│   ├── test_runner.py
│   └── commands.py
│
└── 📦 app/                         ← Source code
    ├── database/                  ← Threat intelligence
    ├── detector/                  ← Email analysis
    ├── dashboard/                 ← Web interface
    └── main.py                    ← FastAPI app
```

---

## 📊 Before vs After

### Before (Messy):
```
phishing-detector/
├── README.md
├── QUICK_START.md
├── EMAIL_DASHBOARD_GUIDE.md      ← Scattered user guides
├── DEMO_MODE_GUIDE.md            ← 
├── DOCUMENTATION_MAP.md          ←
├── COMMIT_GUIDE.md               ←
├── TECHNICAL_REPORT.md           ← Scattered technical docs
├── check_duplicates.py           ← Scattered utilities
├── check_url_matching.py         ←
├── debug_emails.py               ←
├── test_runner.py                ←
├── commands.py                   ←
├── COMMIT_SUMMARY.md             ← Temp files
├── DOCUMENTATION_UPDATES.md      ←
├── SCRIPT_IMPROVEMENTS.txt       ←
├── run.py
├── start.py
├── app/
└── ... 15+ files in root!
```

### After (Clean):
```
phishing-detector/
├── README.md                     ← Entry point
├── QUICK_START.md                ← Quick ref (visible)
├── start.py, run.py              ← Main interfaces
├── requirements.txt, LICENSE     ← Project files
├── setup.sh, run.sh              ← Shell scripts
│
├── docs/                         ← All documentation organized
│   ├── README.md                 ← Doc index
│   ├── guides/                   ← 4 user guides
│   └── technical/                ← 1 technical report
│
├── utils/                        ← All utilities
│   └── 5 utility scripts
│
└── app/                          ← Source code
    └── 3 modules

Only 8-10 items in root!
```

---

## 🗂️ Organization Rules

### Keep in Root
✅ **Main entry points:**
- README.md
- QUICK_START.md (high visibility for new users)

✅ **Primary interfaces:**
- start.py (interactive menu)
- run.py (CLI runner)

✅ **Project essentials:**
- LICENSE
- requirements.txt
- setup/run scripts

### Move to docs/
✅ **User guides:**
- Email Dashboard Guide
- Demo Mode Guide
- Documentation Map
- Commit Guide

✅ **Technical docs:**
- Technical Report

### Move to utils/
✅ **Utility scripts:**
- Diagnostic tools (debug_*, check_*)
- Test runners
- Helper scripts

### Keep in app/
✅ **Source code:**
- All Python modules
- Module-specific READMEs
- Module documentation folders

---

## 📝 Link Updates Made

All links updated to reflect new paths:

| File | Old Link | New Link |
|------|----------|----------|
| README.md | `EMAIL_DASHBOARD_GUIDE.md` | `docs/guides/EMAIL_DASHBOARD_GUIDE.md` |
| README.md | `DEMO_MODE_GUIDE.md` | `docs/guides/DEMO_MODE_GUIDE.md` |
| README.md | `TECHNICAL_REPORT.md` | `docs/technical/TECHNICAL_REPORT.md` |
| README.md | `debug_emails.py` | `utils/debug_emails.py` |
| QUICK_START.md | `EMAIL_DASHBOARD_GUIDE.md` | `docs/guides/EMAIL_DASHBOARD_GUIDE.md` |
| docs/README.md | `../EMAIL_DASHBOARD_GUIDE.md` | `guides/EMAIL_DASHBOARD_GUIDE.md` |

**All links verified** - no broken references!

---

## ✅ Benefits

1. **Cleaner root** - Only 8-10 items instead of 20+
2. **Logical grouping** - docs/, utils/, app/
3. **Easy navigation** - Know where to find things
4. **Professional structure** - Like established projects
5. **Maintained links** - All documentation still connected

---

## 🔍 Finding Things

**User guides:**
```
docs/guides/
```

**Technical docs:**
```
docs/technical/
```

**Utilities:**
```
utils/
```

**Module docs:**
```
app/database/README.md
app/detector/README.md
app/dashboard/README.md
```

---

## 🚀 Commands Still Work

No code changes needed! All paths are relative:

```bash
python run.py demo --once          ✓ Works
python start.py                    ✓ Works
python utils/debug_emails.py       ✓ Works
```

---

**Navigate:** [← Documentation Index](../README.md) | [← Main README](../../README.md)

