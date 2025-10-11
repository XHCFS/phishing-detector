# Dashboard Module

Interactive web interface for visualizing and analyzing threat intelligence data. Built with Streamlit for real-time insights.

## Quick Start

```bash
# Start the dashboard
./run_dashboard.sh

# Or directly
streamlit run app/dashboard/frontend.py
```

Access at: **http://localhost:8501**

---

## Features

- **Multi-Page Interface** - Overview, Analytics, Explorer, Search
- **Interactive Charts** - Plotly visualizations (pie, bar, area, maps)
- **Real-time KPIs** - Total threats, new threats, online count, top source
- **Advanced Filtering** - Text search, multi-select, date ranges
- **Data Export** - CSV and STIX 2.1 formats
- **Geographic Maps** - Visual threat distribution
- **Server-side Pagination** - Efficient large dataset handling

---

## Pages

### 1. Overview
High-level dashboard with KPI metrics and summary charts.

**Charts:**
- Threats by source feed (pie chart)
- Online status distribution (pie chart)
- SSL/TLS status (bar chart)
- Top target brands (horizontal bar)
- Threat detection timeline (area chart - last 30 days)

**KPIs:**
- Total threats
- New threats (7 days)
- Currently online
- Top source feed

---

### 2. Analytics
Deep dive into threat patterns and distributions.

**Charts:**
- Top countries (horizontal bar)
- Geographic map (lat/lon visualization)
- Top ASNs (horizontal bar)
- Domain age distribution (bar chart)

---

### 3. Data Explorer
Browse and search data with advanced filters.

**Features:**
- **Sidebar Filters:**
  - Text search (URL, domain, IP)
  - Source feed (multi-select)
  - Threat type (multi-select)
  - Target brand (multi-select)
  - Country (multi-select)
  - Online status (radio)
  - Date range (first_seen)
  - SSL expiring soon (checkbox)
  - Domain age buckets (multi-select)

- **Data Table:**
  - 50 rows per page (pagination)
  - Sortable columns
  - Row details expander (all 41 fields)

- **Export:**
  - CSV format (for spreadsheets)
  - STIX 2.1 format (for SIEM/TIP)

---

### 4. Search
Quick lookup for specific threats.

**Search Types:**
- URL (LIKE match)
- Domain (LIKE match)
- IP Address (LIKE match)
- Threat ID (exact match)

**Returns:** Up to 10 results with full details

---

## Performance

### Caching
- **Filter options:** 5 minutes
- **Stats/KPIs:** 1 minute
- **Query results:** 1 minute
- **Charts data:** 5 minutes

### Database
- **Connection:** Read-only, shared cache
- **Cache size:** 50,000 pages in memory
- **Temp storage:** Memory (not disk)

### Limits
- **Export:** Max 50,000 rows
- **Map:** Max 2,000 points
- **Pagination:** 50 rows per page

---

## Configuration

### Database Path
**Default:** `app/database/threat_feeds.db`

Change in `frontend.py`:
```python
DB_PATH = Path("/custom/path/threat_feeds.db")
```

### Port
**Default:** 8501

Change:
```bash
streamlit run app/dashboard/frontend.py --server.port 8502
```

### Theme
Create `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#e74c3c"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
```

---

## Usage Examples

### Filtering Example
```
1. Navigate to Data Explorer
2. Sidebar filters:
   - Text search: "login"
   - Source feed: phishtank
   - Online: Yes
   - Date: Last 7 days
3. View filtered table
4. Select row for details
5. Export as CSV or STIX
```

### Search Example
```
1. Navigate to Search page
2. Select search type: URL
3. Enter: "microsoft"
4. View results
5. Expand result for full details
```

### Export Example
```
1. Apply filters in Data Explorer
2. Scroll to "Export Data"
3. Click "Generate CSV" or "Generate STIX"
4. Click download button
5. Save file locally
```

---

## File Structure

```
app/dashboard/
├── README.md                 # This file
├── frontend.py               # Streamlit app (1,500 lines)
├── routes.py                 # FastAPI routes (10 lines)
├── templates/
│   └── index.html            # HTML template
└── Documentation/
    └── DASHBOARD_GUIDE.md    # Complete technical guide (850 lines)
```

---

## Troubleshooting

### Dashboard Won't Start

**"Database not found"**
```bash
# Create and populate database
python -m app.database.db
python -m app.database.enrich --limit 100
```

**"Port already in use"**
```bash
# Kill existing process
pkill -f streamlit

# Or use different port
streamlit run app/dashboard/frontend.py --server.port 8502
```

### No Data in Charts

**Check database has data:**
```bash
sqlite3 app/database/threat_feeds.db "SELECT COUNT(*) FROM enriched_threats"

# If 0, enrich data
python -m app.database.enrich --limit 500
```

### Slow Performance

**Increase cache TTL:**
```python
# Edit frontend.py
@st.cache_data(ttl=600)  # 10 minutes
```

**Reduce data size:**
```bash
# Process fewer URLs
# Clean old data from database
```

---

## Documentation

- **[DASHBOARD_GUIDE.md](Documentation/DASHBOARD_GUIDE.md)** - Complete technical documentation (850 lines)
  - System architecture
  - Component details
  - Chart configurations
  - Performance optimization
  - Comprehensive troubleshooting

---

## Dependencies

```bash
# Required
pip install streamlit plotly pandas

# Included with Python
import sqlite3
```

See `requirements.txt` for versions.

---

## Summary

**Purpose:** Real-time threat intelligence visualization

**Technology:** Streamlit + Plotly + SQLite

**Performance:** 1-3s page load, <1s cached

**Best For:**
- Threat analysts viewing data
- Security teams monitoring threats
- Researchers analyzing patterns
- Exporting data for reports

**Access:** http://localhost:8501 (default)

---

Ready to visualize threats!
