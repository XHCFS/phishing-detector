# Dashboard Module - Complete Technical Guide

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Frontend Components](#frontend-components)
4. [Data Visualization](#data-visualization)
5. [Performance Optimization](#performance-optimization)
6. [API Routes](#api-routes)
7. [Usage Guide](#usage-guide)
8. [Configuration](#configuration)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The **Dashboard Module** provides an interactive web interface for visualizing and analyzing threat intelligence data. Built with **Streamlit**, it offers real-time insights into phishing threats, URL patterns, and geographic distributions.

**Key Features:**
- ✅ Multi-page navigation (Overview, Analytics, Data Explorer, Search)
- ✅ Interactive charts with Plotly
- ✅ Real-time KPI metrics
- ✅ Geographic map visualization
- ✅ Advanced filtering and search
- ✅ Data export (CSV, STIX 2.1)
- ✅ Server-side pagination
- ✅ Responsive design

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DASHBOARD MODULE                          │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐
│   frontend.py│  (Streamlit App - 1500 lines)
│              │
│  ┌──────────┼──────────────────────────────────────┐
│  │ Pages:   │                                       │
│  │          │                                       │
│  │ Overview │ → KPIs, charts, timeline            │
│  │ Analytics│ → Deep dive, geographic analysis    │
│  │ Explorer │ → Data table, filters, export        │
│  │ Search   │ → Quick lookup by URL/domain/IP     │
│  └──────────┼──────────────────────────────────────┘
│              │
│  ┌──────────▼──────────────────────────────────────┐
│  │ Database Queries (cached)                       │
│  │                                                  │
│  │ • get_filter_options()    - Multi-select values │
│  │ • get_stats()             - KPI metrics         │
│  │ • get_rows()              - Paginated data      │
│  │ • get_row_details()       - Full record         │
│  │ • get_map_points()        - Geo coordinates     │
│  │ • get_analytics_data()    - Chart data          │
│  │ • export_to_csv()         - CSV export          │
│  │ • export_to_stix()        - STIX 2.1 export     │
│  └──────────┬──────────────────────────────────────┘
│             │
│  ┌──────────▼──────────────────────────────────────┐
│  │ SQLite Connection (read-only)                   │
│  │                                                  │
│  │ • PRAGMA cache_size=50000                       │
│  │ • PRAGMA temp_store=MEMORY                      │
│  │ • Connection pooling                            │
│  └──────────┬──────────────────────────────────────┘
│             │
└─────────────┼──────────────────────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │ threat_feeds.db     │
    │ (enriched_threats)  │
    └─────────────────────┘

┌──────────────┐
│   routes.py  │  (FastAPI Routes - 10 lines)
│              │
│  GET /dashboard/  → Renders index.html
│                   ↓
│              templates/index.html
└──────────────┘
```

---

## Frontend Components

### 1. `frontend.py` (1,500 lines)

**Purpose:** Main Streamlit application with multi-page navigation and interactive visualizations

#### Key Components

##### Multi-Page Navigation

```python
def main():
    # Sidebar navigation
    page = st.sidebar.radio(
        "Select Page:",
        options=["Overview", "Analytics", "Data Explorer", "Search"]
    )
    
    # Route to appropriate page
    if page == "Overview":
        render_overview_page()
    elif page == "Analytics":
        render_analytics_page()
    elif page == "Data Explorer":
        render_data_explorer_page()
    elif page == "Search":
        render_search_page()
```

##### Database Connection

```python
@st.cache_resource
def get_db_connection():
    """Get read-only database connection with performance optimizations."""
    db_uri = f"file:{DB_PATH}?mode=ro&cache=shared"
    conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False)
    
    # Performance pragmas
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=50000")
    
    conn.row_factory = sqlite3.Row
    return conn
```

**Features:**
- **Read-only mode:** Prevents accidental modifications
- **Shared cache:** Multiple connections share cache
- **Performance pragmas:** Optimize query execution
- **Row factory:** Named column access

##### Filtering System

```python
def build_where_clause(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    """
    Build parameterized WHERE clause from filters.
    
    Supports:
    - Text search (url, domain, ip_address)
    - Multi-select (source_feed, threat_type, country)
    - Radio buttons (online status)
    - Date ranges (first_seen)
    - Toggles (SSL expiring, domain age)
    """
    conditions = []
    params = []
    
    # Text search
    if filters.get('text_search'):
        search_term = f"%{filters['text_search']}%"
        conditions.append(
            "(url LIKE ? OR domain LIKE ? OR ip_address LIKE ?)"
        )
        params.extend([search_term, search_term, search_term])
    
    # Multi-select filters
    if filters.get('source_feeds'):
        placeholders = ','.join('?' * len(filters['source_feeds']))
        conditions.append(f"source_feed IN ({placeholders})")
        params.extend(filters['source_feeds'])
    
    # ... more filters ...
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    return where_clause, params
```

**Supported Filters:**

| Filter Type | Fields | Description |
|-------------|--------|-------------|
| **Text Search** | url, domain, ip_address | LIKE search across multiple columns |
| **Multi-Select** | source_feed, threat_type, target_brand, country | IN clause with multiple values |
| **Radio** | online status | Single selection (All, Yes, No, Unknown) |
| **Date Range** | first_seen | Between two dates |
| **Toggle** | SSL expiring soon | Custom date calculation |
| **Checkbox** | Domain age buckets | Multiple age ranges |

##### Caching Strategy

```python
@st.cache_data(ttl=300)  # 5 minutes
def get_filter_options() -> Dict[str, List[str]]:
    """Get available options for multi-select filters."""
    # ... fetch distinct values from database ...
    pass

@st.cache_data(ttl=60)  # 1 minute
def get_stats(where_clause: str, params: List[Any]) -> Dict[str, Any]:
    """Get KPI statistics for filtered data."""
    # ... calculate metrics ...
    pass

@st.cache_data(ttl=60)
def get_rows(...):
    """Get paginated rows from database."""
    # ... fetch data ...
    pass
```

**Cache Levels:**

| Function | TTL | Reason |
|----------|-----|--------|
| `get_filter_options()` | 5 min | Filter values change rarely |
| `get_stats()` | 1 min | KPIs updated frequently |
| `get_rows()` | 1 min | Data changes often |
| `get_analytics_data()` | 5 min | Chart data stable |

---

### 2. `routes.py` (10 lines)

**Purpose:** FastAPI routes for serving the dashboard web interface

```python
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))

@router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Dashboard"})
```

**Endpoint:**
- **`GET /dashboard/`** → Renders `index.html` template

**Note:** The actual Streamlit dashboard runs as a separate process (see Usage Guide).

---

## Data Visualization

### Page Layouts

#### 1. Overview Page

**Purpose:** High-level summary of threat landscape

**Components:**

##### KPI Metrics
```python
def render_kpis(stats: Dict[str, Any]):
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Threats",
            value=f"{stats['total']:,}"
        )
    
    with col2:
        st.metric(
            label="New (7 Days)",
            value=f"{stats['new_7d']:,}",
            delta=f"{100*stats['new_7d']/max(stats['total'], 1):.1f}%"
        )
    # ... more metrics ...
```

**Metrics Displayed:**
- **Total Threats:** Count of all records
- **New (7 Days):** Threats added in last 7 days (with % delta)
- **Currently Online:** Active threats (with % delta)
- **Top Source:** Most common feed source (with count)

##### Charts

**1. Threats by Source Feed (Pie Chart)**
```python
fig = px.pie(
    analytics['by_source'],
    values='count',
    names='source',
    hole=0.4,  # Donut chart
    color_discrete_sequence=px.colors.qualitative.Set3
)
fig.update_traces(textposition='inside', textinfo='percent+label')
```

**2. Online Status Distribution (Pie Chart with Custom Colors)**
```python
colors = {
    'Online': '#2ecc71',   # Green
    'Offline': '#e74c3c',  # Red
    'Unknown': '#95a5a6'   # Gray
}
fig = go.Figure(data=[go.Pie(
    labels=analytics['by_status']['status'],
    values=analytics['by_status']['count'],
    marker=dict(colors=[colors.get(s, '#3498db') for s in analytics['by_status']['status']]),
    hole=0.4
)])
```

**3. SSL/TLS Status (Bar Chart)**
```python
colors = {
    'SSL Enabled': '#27ae60',
    'No SSL': '#e67e22',
    'Unknown': '#95a5a6'
}
fig = go.Figure(data=[go.Bar(
    x=analytics['by_ssl']['status'],
    y=analytics['by_ssl']['count'],
    marker=dict(color=[colors.get(s, '#3498db') for s in analytics['by_ssl']['status']]),
    text=analytics['by_ssl']['count'],
    textposition='outside'
)])
```

**4. Top Target Brands (Horizontal Bar Chart)**
```python
fig = px.bar(
    analytics['by_brand'],
    x='count',
    y='brand',
    orientation='h',
    color='count',
    color_continuous_scale='Reds'
)
fig.update_layout(yaxis={'categoryorder': 'total ascending'})
```

**5. Threat Detection Timeline (Area Chart)**
```python
fig = px.area(
    analytics['timeline'],
    x='date',
    y='count',
    color_discrete_sequence=['#3498db']
)
fig.update_traces(fill='tozeroy', line=dict(width=2))
```

---

#### 2. Analytics Page

**Purpose:** Deep dive into threat patterns and distributions

**Charts:**

**1. Top Countries by Threat Count (Horizontal Bar Chart)**
```python
fig = px.bar(
    analytics['by_country'],
    x='count',
    y='country',
    orientation='h',
    color='count',
    color_continuous_scale='Plasma',
    hover_data=['code']
)
```

**2. Geographic Map**
```python
map_data = get_map_points(where_clause, params, limit=500)
st.map(map_data, latitude='lat', longitude='lon', size=20)
```

**3. Top Autonomous Systems (ASN)**
```python
fig = px.bar(
    analytics['by_asn'],
    x='count',
    y='asn',
    orientation='h',
    color='count',
    color_continuous_scale='Blues'
)
```

**4. Domain Age Distribution**
```python
fig = px.bar(
    analytics['by_age'],
    x='age',
    y='count',
    color='count',
    color_continuous_scale='Viridis'
)
```

**Age Buckets:**
- 0-30 days (New)
- 31-90 days
- 91-180 days
- 181-365 days
- 1+ years (Established)

---

#### 3. Data Explorer Page

**Purpose:** Browse and search threat intelligence data with filters

**Components:**

**1. Sidebar Filters**
```python
def render_sidebar_filters() -> Dict[str, Any]:
    filters = {}
    
    # Text search
    filters['text_search'] = st.sidebar.text_input(
        "Search",
        placeholder="URL, domain, or IP address"
    )
    
    # Multi-select filters
    filters['source_feeds'] = st.sidebar.multiselect(
        "Source Feed",
        options=options['source_feeds']
    )
    
    # Date range
    filters['date_from'] = st.sidebar.date_input("From", value=None)
    filters['date_to'] = st.sidebar.date_input("To", value=None)
    
    # Advanced filters
    filters['ssl_expiring_soon'] = st.sidebar.checkbox(
        "SSL Expiring <30 Days"
    )
    
    return filters
```

**2. Data Table with Pagination**
```python
def render_main_table(df: pd.DataFrame, total: int, page: int, page_size: int):
    # Show current page info
    start_idx = page * page_size + 1
    end_idx = min((page + 1) * page_size, total)
    st.caption(f"Showing {start_idx:,} - {end_idx:,} of {total:,} threats")
    
    # Format and display table
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    
    # Pagination controls
    total_pages = (total + page_size - 1) // page_size
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        if page > 0:
            if st.button("← Previous"):
                st.session_state.page = page - 1
                st.rerun()
    
    with col3:
        if page < total_pages - 1:
            if st.button("Next →"):
                st.session_state.page = page + 1
                st.rerun()
```

**3. Row Details Expander**
```python
def render_detail_view(details: Dict[str, Any]):
    # Basic Information
    st.markdown("#### Basic Information")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("URL", value=details.get('url', 'N/A'), disabled=True)
        st.text_input("Domain", value=details.get('domain', 'N/A'), disabled=True)
    with col2:
        st.text_input("IP Address", value=details.get('ip_address', 'N/A'), disabled=True)
        st.text_input("Online Status", value=online_display, disabled=True)
    
    # Network & Geographic Information
    # SSL/TLS Information
    # Domain Registration
    # Content & Threat Classification
    # Source & Tracking
    # ... (all 41 fields displayed)
```

**4. Export Section**
```python
def render_export_section(where_clause: str, params: List[Any], total: int):
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### CSV Format")
        if st.button("Generate CSV"):
            csv_data = export_to_csv(where_clause, params, MAX_EXPORT_ROWS)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"threat_intel_export_{timestamp}.csv",
                mime='text/csv'
            )
    
    with col2:
        st.markdown("#### STIX 2.1 Format")
        if st.button("Generate STIX"):
            stix_data = export_to_stix(where_clause, params, MAX_EXPORT_ROWS)
            st.download_button(
                label="Download STIX JSON",
                data=stix_data,
                file_name=f"threat_intel_export_{timestamp}.json",
                mime='application/json'
            )
```

---

#### 4. Search Page

**Purpose:** Quick lookup for specific threats

**Features:**

**Search Types:**
- URL (LIKE match)
- Domain (LIKE match)
- IP Address (LIKE match)
- Threat ID (exact match)

**Example:**
```python
def render_search_page():
    search_type = st.radio(
        "Search by:",
        options=['URL', 'Domain', 'IP Address', 'Threat ID'],
        horizontal=True
    )
    
    search_term = st.text_input(f"Enter {search_type}")
    
    if search_term:
        # Execute search query
        results = execute_search(search_type, search_term)
        
        # Display results
        for result in results:
            with st.expander(f"{result['url'][:80]}...", expanded=len(results)==1):
                render_detail_view(result)
```

---

## Performance Optimization

### Caching Strategy

**1. Resource Caching (Database Connection)**
```python
@st.cache_resource
def get_db_connection():
    # Cached globally across all sessions
    # Never expires until app restarts
    pass
```

**2. Data Caching (Query Results)**
```python
@st.cache_data(ttl=300)  # 5 minutes
def get_filter_options():
    # Cached per unique input arguments
    # Expires after 5 minutes
    pass

@st.cache_data(ttl=60)  # 1 minute
def get_stats(where_clause, params):
    # Cached per unique filter combination
    # Expires after 1 minute
    pass
```

**Cache Invalidation:**
- **Time-based:** TTL (Time To Live) expiration
- **Automatic:** Streamlit cache management
- **Manual:** Not needed for read-only dashboard

### Query Optimization

**1. Indexes Used:**
```sql
-- In enriched_threats table
CREATE INDEX idx_enriched_domain ON enriched_threats(domain)
CREATE INDEX idx_enriched_ip ON enriched_threats(ip_address)
CREATE INDEX idx_enriched_asn ON enriched_threats(asn)
CREATE INDEX idx_enriched_country ON enriched_threats(country)
CREATE INDEX idx_enriched_source ON enriched_threats(source_feed)
CREATE INDEX idx_enriched_online ON enriched_threats(online)
CREATE INDEX idx_enriched_tld ON enriched_threats(tld)
CREATE INDEX idx_enriched_threat_type ON enriched_threats(threat_type)
CREATE INDEX idx_enriched_first_seen ON enriched_threats(first_seen)
CREATE INDEX idx_enriched_risk_score ON enriched_threats(risk_score)
```

**2. Pagination:**
```sql
SELECT * FROM enriched_threats
WHERE <filters>
ORDER BY first_seen DESC
LIMIT ? OFFSET ?  -- Server-side pagination
```

**3. Aggregation:**
```sql
-- Efficient GROUP BY queries
SELECT country, COUNT(*) as count
FROM enriched_threats
WHERE <filters>
GROUP BY country
ORDER BY count DESC
LIMIT 15
```

### Performance Settings

```python
# Configuration constants
MAX_EXPORT_ROWS = 50000   # Limit export size
MAX_MAP_POINTS = 2000     # Limit map markers
ROWS_PER_PAGE = 50        # Pagination size
```

**Database Pragmas:**
```python
conn.execute("PRAGMA temp_store=MEMORY")     # Use RAM for temp tables
conn.execute("PRAGMA cache_size=50000")      # Large cache (50,000 pages)
```

### Load Time Benchmarks

| Page | Load Time | Cached Load Time |
|------|-----------|------------------|
| Overview | ~2-3s | <1s |
| Analytics | ~3-4s | ~1s |
| Data Explorer | ~1-2s | <1s |
| Search | <1s | <0.5s |

---

## API Routes

### FastAPI Endpoints

**Base URL:** `http://localhost:8000/dashboard`

#### `GET /dashboard/`
Renders the dashboard home page.

**Response:** HTML template (`index.html`)

**Usage:**
```bash
# Open in browser
http://localhost:8000/dashboard/
```

**Note:** This is a placeholder. The actual Streamlit dashboard runs separately on port 8501.

---

## Usage Guide

### Starting the Dashboard

#### Method 1: Using run_dashboard.sh
```bash
# Start Streamlit dashboard
./run_dashboard.sh
```

#### Method 2: Direct Streamlit Command
```bash
# Start on default port (8501)
streamlit run app/dashboard/frontend.py

# Custom port
streamlit run app/dashboard/frontend.py --server.port 8502
```

#### Method 3: From Python
```python
import os
os.system("streamlit run app/dashboard/frontend.py")
```

### Accessing the Dashboard

**Default URL:** `http://localhost:8501`

**Navigation:**
- Sidebar → Select page (Overview, Analytics, Data Explorer, Search)
- Filters → Apply filters in sidebar (Data Explorer page)
- Tables → Click rows to see details
- Charts → Hover for tooltips, click legend to toggle series

### Filtering Data

**Example Workflow:**

1. **Navigate to Data Explorer page**
2. **Apply filters in sidebar:**
   - Text search: `login`
   - Source: `phishtank`
   - Online: `Yes`
   - Date: Last 7 days
3. **View filtered results in table**
4. **Select row to see full details**
5. **Export filtered data:**
   - CSV for spreadsheets
   - STIX for SIEM integration

### Exporting Data

#### CSV Export
```
1. Apply filters
2. Scroll to "Export Data" section
3. Click "Generate CSV"
4. Click "Download CSV"
5. Open in Excel/LibreOffice
```

**CSV Fields:** All 41 enriched_threats columns

#### STIX 2.1 Export
```
1. Apply filters
2. Click "Generate STIX"
3. Click "Download STIX JSON"
4. Import into SIEM/TIP (e.g., MISP, OpenCTI)
```

**STIX Format:**
```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--...",
      "name": "Phishing URL: example.com",
      "pattern": "[url:value = 'https://example.com/phish']",
      "indicator_types": ["malicious-activity"],
      "labels": ["phishing", "targets-Microsoft"],
      "x_ip_address": "1.2.3.4",
      "x_country": "US"
    }
  ]
}
```

### Searching Threats

**Example Searches:**

**By URL:**
```
Search Type: URL
Query: microsoft.com
Results: All URLs containing "microsoft.com"
```

**By Domain:**
```
Search Type: Domain
Query: .zip
Results: All domains with .zip TLD
```

**By IP:**
```
Search Type: IP Address
Query: 192.168
Results: All threats hosted on 192.168.x.x
```

**By ID:**
```
Search Type: Threat ID
Query: 12345
Results: Exact match for ID=12345
```

---

## Configuration

### Streamlit Configuration

**`.streamlit/config.toml` (optional):**
```toml
[server]
port = 8501
headless = true

[theme]
primaryColor = "#e74c3c"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"

[browser]
gatherUsageStats = false
```

### Database Path

**Default:** `app/database/threat_feeds.db`

**Change:**
```python
# Edit frontend.py
DB_PATH = Path("/custom/path/threat_feeds.db")
```

### Performance Tuning

**Cache TTL:**
```python
# Edit frontend.py
@st.cache_data(ttl=600)  # 10 minutes (longer cache)
def get_filter_options():
    pass
```

**Pagination Size:**
```python
# Edit frontend.py
ROWS_PER_PAGE = 100  # More rows per page
```

**Map Points Limit:**
```python
# Edit frontend.py
MAX_MAP_POINTS = 5000  # More map markers
```

---

## Troubleshooting

### Dashboard Won't Start

**Problem:** "Database not found"
```bash
# Solution: Create and populate database
python -m app.database.db
python -m app.database.grabrawdata
python -m app.database.enrich --limit 100
```

**Problem:** "Port already in use"
```bash
# Solution: Kill existing Streamlit process
pkill -f streamlit

# Or use different port
streamlit run app/dashboard/frontend.py --server.port 8502
```

**Problem:** "Module not found: streamlit"
```bash
# Solution: Install dependencies
pip install streamlit plotly pandas
```

### Performance Issues

**Problem:** "Dashboard is slow"
```
# Solution 1: Increase cache TTL
# Edit frontend.py, increase ttl values

# Solution 2: Reduce data size
# Process fewer URLs, clean old data

# Solution 3: Optimize queries
# Add indexes, use LIMIT clauses
```

**Problem:** "Charts not loading"
```
# Solution: Check data availability
sqlite3 app/database/threat_feeds.db \
  "SELECT COUNT(*) FROM enriched_threats"

# If 0, enrich some data
python -m app.database.enrich --limit 500
```

### Data Issues

**Problem:** "No data in charts"
```
# Solution: Verify database has data
sqlite3 app/database/threat_feeds.db \
  "SELECT source_feed, COUNT(*) FROM enriched_threats GROUP BY source_feed"
```

**Problem:** "Map shows no points"
```
# Solution: Check for latitude/longitude data
sqlite3 app/database/threat_feeds.db \
  "SELECT COUNT(*) FROM enriched_threats WHERE latitude IS NOT NULL"

# If 0, enrich with GeoIP data
python -m app.database.enrich --limit 1000
```

**Problem:** "Export fails"
```
# Solution: Check database permissions
ls -l app/database/threat_feeds.db

# Ensure read access
chmod 644 app/database/threat_feeds.db
```

### Browser Issues

**Problem:** "Dashboard doesn't load in browser"
```
# Solution 1: Clear browser cache
# Ctrl+Shift+R (hard refresh)

# Solution 2: Try different browser
# Chrome, Firefox, Safari

# Solution 3: Check network
# Firewall blocking port 8501?
```

---

## Summary

### Key Features
✅ **Multi-page Interface** - Overview, Analytics, Explorer, Search
✅ **Interactive Charts** - Plotly visualizations with hover tooltips
✅ **Advanced Filtering** - Multi-select, date ranges, text search
✅ **Server-side Pagination** - Efficient handling of large datasets
✅ **Data Export** - CSV and STIX 2.1 formats
✅ **Real-time KPIs** - Metrics with trend indicators
✅ **Geographic Maps** - Visual threat distribution

### Technology Stack
- **Frontend:** Streamlit 1.28+
- **Charts:** Plotly Express & Graph Objects
- **Database:** SQLite (read-only mode)
- **Backend:** FastAPI (placeholder route)

### Performance
- **Page Load:** 1-3 seconds (first load), <1 second (cached)
- **Query Cache:** 1-5 minute TTL
- **Database Cache:** 50,000 pages in memory
- **Max Export:** 50,000 rows
- **Max Map Points:** 2,000 markers

### Best Practices
1. Run enrichment before viewing dashboard
2. Use filters to narrow results
3. Export filtered data for offline analysis
4. Clear cache if data seems stale (Ctrl+R in Streamlit)
5. Monitor database size (prune old data periodically)

---

**Last Updated:** October 12, 2025  
**Module Version:** 1.0  
**Dependencies:** streamlit, plotly, pandas, sqlite3
