# 🗺️ Documentation Navigation Map

**Complete linking structure for all documentation files.**

---

## 📍 Start Here

```
README.md (Main entry point)
    ↓
    ├──→ QUICK_START.md (For users)
    │    └──→ EMAIL_DASHBOARD_GUIDE.md
    │         └──→ DEMO_MODE_GUIDE.md
    │
    ├──→ docs/README.md (Documentation index)
    │    ├──→ All user guides
    │    ├──→ All technical guides
    │    └──→ All module READMEs
    │
    └──→ TECHNICAL_REPORT.md (For developers/researchers)
```

---

## 🎯 User Journey

### New User Path
```
1. README.md
   ↓
2. QUICK_START.md
   ↓
3. Run: python run.py demo --once
   ↓
4. EMAIL_DASHBOARD_GUIDE.md
   ↓
5. DEMO_MODE_GUIDE.md
```

### Developer Path
```
1. README.md
   ↓
2. TECHNICAL_REPORT.md
   ↓
3. Module READMEs
   ├── app/database/README.md
   ├── app/detector/README.md
   └── app/dashboard/README.md
   ↓
4. Technical Guides
   ├── DATABASE_GUIDE.md
   ├── DETECTOR_GUIDE.md
   └── DASHBOARD_GUIDE.md
```

---

## 📚 Document Hierarchy

### Level 1: Entry Points
- **README.md** - Main project README
- **QUICK_START.md** - Fast getting started guide
- **docs/README.md** - Complete documentation index

### Level 2: Feature Guides
- **EMAIL_DASHBOARD_GUIDE.md** - Email monitoring usage
- **DEMO_MODE_GUIDE.md** - Automated monitoring
- **start.py** - Interactive menu (executable)

### Level 3: Module Documentation
- **app/database/README.md** - Database quick start
- **app/detector/README.md** - Detector quick start
- **app/dashboard/README.md** - Dashboard quick start
- **app/README.md** - Application module overview

### Level 4: Technical Details
- **TECHNICAL_REPORT.md** - System design and evaluation
- **app/database/Documentation & Sources Research/DATABASE_GUIDE.md**
- **app/detector/Documentation/DETECTOR_GUIDE.md**
- **app/dashboard/Documentation/DASHBOARD_GUIDE.md**
- **app/database/Documentation & Sources Research/Data Sources.md**

### Level 5: Utilities
- **check_duplicates.py** - Database diagnostics
- **check_url_matching.py** - URL matching tests
- **debug_emails.py** - Email database diagnostics

---

## 🔗 Cross-Reference Matrix

| From | Links To |
|------|----------|
| **README.md** | QUICK_START.md, EMAIL_DASHBOARD_GUIDE.md, DEMO_MODE_GUIDE.md, docs/README.md, all module READMEs, TECHNICAL_REPORT.md |
| **QUICK_START.md** | README.md, EMAIL_DASHBOARD_GUIDE.md, DEMO_MODE_GUIDE.md, docs/README.md |
| **EMAIL_DASHBOARD_GUIDE.md** | QUICK_START.md, README.md, DEMO_MODE_GUIDE.md, app/dashboard/README.md, docs/README.md |
| **DEMO_MODE_GUIDE.md** | QUICK_START.md, EMAIL_DASHBOARD_GUIDE.md, README.md, app/detector/README.md, docs/README.md |
| **docs/README.md** | ALL documents (master index) |
| **app/database/README.md** | DATABASE_GUIDE.md, Data Sources.md, docs/README.md, README.md |
| **app/detector/README.md** | DETECTOR_GUIDE.md, docs/README.md, README.md |
| **app/dashboard/README.md** | DASHBOARD_GUIDE.md, EMAIL_DASHBOARD_GUIDE.md, docs/README.md, README.md |

---

## 🎯 Documentation Goals Achieved

✅ **No isolated documents** - Every MD links to at least 3 others  
✅ **Clear hierarchy** - Entry point → Feature guides → Module docs → Technical details  
✅ **Multiple pathways** - User, developer, and researcher journeys  
✅ **Bidirectional links** - Can navigate up, down, and across  
✅ **Quick access** - Related docs linked at bottom of each file  
✅ **Central index** - docs/README.md as master navigation  

---

## 🗂️ File Locations

```
Root Level (User-facing):
  README.md
  QUICK_START.md
  EMAIL_DASHBOARD_GUIDE.md
  DEMO_MODE_GUIDE.md
  TECHNICAL_REPORT.md
  start.py

Documentation Directory:
  docs/README.md (Master index)

Module Documentation:
  app/README.md
  app/database/README.md
  app/database/Documentation & Sources Research/
    ├── DATABASE_GUIDE.md
    └── Data Sources.md
  app/detector/README.md
  app/detector/Documentation/
    └── DETECTOR_GUIDE.md
  app/dashboard/README.md
  app/dashboard/Documentation/
    └── DASHBOARD_GUIDE.md

Utilities:
  check_duplicates.py
  check_url_matching.py
  debug_emails.py
```

---

## 📝 Quick Find

**I want to...**

| Task | Document |
|------|----------|
| Get started quickly | [QUICK_START.md](QUICK_START.md) |
| Use the dashboard | [EMAIL_DASHBOARD_GUIDE.md](EMAIL_DASHBOARD_GUIDE.md) |
| Run continuous monitoring | [DEMO_MODE_GUIDE.md](DEMO_MODE_GUIDE.md) |
| Understand the system | [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) |
| Set up database | [app/database/README.md](app/database/README.md) |
| Configure email detection | [app/detector/README.md](app/detector/README.md) |
| Customize dashboard | [app/dashboard/README.md](app/dashboard/README.md) |
| Find all documentation | [docs/README.md](docs/README.md) |
| Debug issues | check_*.py, debug_*.py utilities |

---

**Navigate:** [→ Documentation Index](../README.md) | [→ Main README](../../README.md) | [→ Quick Start](../../QUICK_START.md)

