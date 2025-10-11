#!/usr/bin/env python3
"""
Streamlit dashboard for threat feeds database.

Multi-page app that reads directly from SQLite enriched_threats table.
Features:
- Multi-page navigation (Overview, Analytics, Data Explorer, Search)
- Interactive charts and visualizations
- Server-side filtering and pagination
- KPI metrics with trend indicators
- Geographic map visualization
- CSV export
"""

import sqlite3
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any
import plotly.express as px
import plotly.graph_objects as go

# Database configuration
DB_DIR = Path(__file__).parent.parent / "database"
DB_PATH = DB_DIR / "threat_feeds.db"

# Performance settings
MAX_EXPORT_ROWS = 50000
MAX_MAP_POINTS = 2000
ROWS_PER_PAGE = 50

# Configure Streamlit page
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="�",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================================
# Database Connection and Query Helpers
# ============================================================================

@st.cache_resource
def get_db_connection():
    """Get read-only database connection with performance optimizations."""
    db_uri = f"file:{DB_PATH}?mode=ro&cache=shared"
    conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False)
    
    # Performance pragmas (read-only mode may ignore some)
    try:
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=50000")
    except sqlite3.OperationalError:
        pass  # Ignore errors in read-only mode
    
    conn.row_factory = sqlite3.Row
    return conn


def build_where_clause(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    """
    Build parameterized WHERE clause from filters.
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        Tuple of (where_clause_sql, parameters_list)
    """
    conditions = []
    params = []
    
    # Text search across url/domain/ip_address
    if filters.get('text_search'):
        search_term = f"%{filters['text_search']}%"
        conditions.append(
            "(url LIKE ? OR domain LIKE ? OR ip_address LIKE ?)"
        )
        params.extend([search_term, search_term, search_term])
    
    # Multi-select: source_feed
    if filters.get('source_feeds'):
        placeholders = ','.join('?' * len(filters['source_feeds']))
        conditions.append(f"source_feed IN ({placeholders})")
        params.extend(filters['source_feeds'])
    
    # Multi-select: threat_type
    if filters.get('threat_types'):
        placeholders = ','.join('?' * len(filters['threat_types']))
        conditions.append(f"threat_type IN ({placeholders})")
        params.extend(filters['threat_types'])
    
    # Multi-select: target_brand
    if filters.get('target_brands'):
        placeholders = ','.join('?' * len(filters['target_brands']))
        conditions.append(f"target_brand IN ({placeholders})")
        params.extend(filters['target_brands'])
    
    # Multi-select: country
    if filters.get('countries'):
        placeholders = ','.join('?' * len(filters['countries']))
        conditions.append(f"country IN ({placeholders})")
        params.extend(filters['countries'])
    
    # Radio: online status
    if filters.get('online_status') and filters['online_status'] != 'All':
        conditions.append("online = ?")
        params.append(filters['online_status'].lower())
    
    # Date range: first_seen
    if filters.get('date_from'):
        conditions.append("date(first_seen) >= ?")
        params.append(filters['date_from'].isoformat())
    
    if filters.get('date_to'):
        conditions.append("date(first_seen) <= ?")
        params.append(filters['date_to'].isoformat())
    
    # Toggle: SSL expiring soon (<30 days)
    if filters.get('ssl_expiring_soon'):
        conditions.append(
            "cert_valid_to IS NOT NULL AND "
            "julianday(cert_valid_to) - julianday('now') BETWEEN 0 AND 30"
        )
    
    # Toggle: Domain age buckets
    if filters.get('domain_age_buckets'):
        age_conditions = []
        if 'new' in filters['domain_age_buckets']:  # ≤30 days
            age_conditions.append(
                "(creation_date IS NOT NULL AND "
                "julianday('now') - julianday(creation_date) <= 30)"
            )
        if 'medium' in filters['domain_age_buckets']:  # 31-180 days
            age_conditions.append(
                "(creation_date IS NOT NULL AND "
                "julianday('now') - julianday(creation_date) "
                "BETWEEN 31 AND 180)"
            )
        if 'old' in filters['domain_age_buckets']:  # >180 days
            age_conditions.append(
                "(creation_date IS NOT NULL AND "
                "julianday('now') - julianday(creation_date) > 180)"
            )
        if age_conditions:
            conditions.append(f"({' OR '.join(age_conditions)})")
    
    # Combine all conditions
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    return where_clause, params


@st.cache_data(ttl=300)
def get_filter_options() -> Dict[str, List[str]]:
    """Get available options for multi-select filters (cached for 5 min)."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    options = {}
    
    # Get distinct source feeds
    cur.execute(
        "SELECT DISTINCT source_feed FROM enriched_threats "
        "WHERE source_feed IS NOT NULL ORDER BY source_feed"
    )
    options['source_feeds'] = [row[0] for row in cur.fetchall()]
    
    # Get distinct threat types
    cur.execute(
        "SELECT DISTINCT threat_type FROM enriched_threats "
        "WHERE threat_type IS NOT NULL ORDER BY threat_type"
    )
    options['threat_types'] = [row[0] for row in cur.fetchall()]
    
    # Get distinct target brands (limit to top 100 by frequency)
    cur.execute(
        "SELECT target_brand, COUNT(*) as cnt FROM enriched_threats "
        "WHERE target_brand IS NOT NULL "
        "GROUP BY target_brand ORDER BY cnt DESC LIMIT 100"
    )
    options['target_brands'] = [row[0] for row in cur.fetchall()]
    
    # Get distinct countries
    cur.execute(
        "SELECT DISTINCT country FROM enriched_threats "
        "WHERE country IS NOT NULL ORDER BY country"
    )
    options['countries'] = [row[0] for row in cur.fetchall()]
    
    cur.close()
    return options


@st.cache_data(ttl=60)
def get_stats(where_clause: str, params: List[Any]) -> Dict[str, Any]:
    """Get KPI statistics for filtered data."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    stats = {}
    
    # Total count
    cur.execute(
        f"SELECT COUNT(*) FROM enriched_threats WHERE {where_clause}",
        params
    )
    stats['total'] = cur.fetchone()[0]
    
    # New in last 7 days
    seven_days_ago = (
        datetime.now(timezone.utc) - timedelta(days=7)
    ).isoformat()
    cur.execute(
        f"SELECT COUNT(*) FROM enriched_threats "
        f"WHERE {where_clause} AND first_seen >= ?",
        params + [seven_days_ago]
    )
    stats['new_7d'] = cur.fetchone()[0]
    
    # Online count
    cur.execute(
        f"SELECT COUNT(*) FROM enriched_threats "
        f"WHERE {where_clause} AND online = 'yes'",
        params
    )
    stats['online'] = cur.fetchone()[0]
    
    # Top source feed
    cur.execute(
        f"SELECT source_feed, COUNT(*) as cnt FROM enriched_threats "
        f"WHERE {where_clause} AND source_feed IS NOT NULL "
        f"GROUP BY source_feed ORDER BY cnt DESC LIMIT 1",
        params
    )
    result = cur.fetchone()
    stats['top_source'] = result[0] if result else 'N/A'
    stats['top_source_count'] = result[1] if result else 0
    
    cur.close()
    return stats


@st.cache_data(ttl=60)
def get_rows(
    where_clause: str,
    params: List[Any],
    limit: int,
    offset: int,
    order_by: str = "first_seen DESC"
) -> Tuple[pd.DataFrame, int]:
    """
    Get paginated rows from database.
    
    Returns:
        Tuple of (dataframe, total_count)
    """
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Get total count
    cur.execute(
        f"SELECT COUNT(*) FROM enriched_threats WHERE {where_clause}",
        params
    )
    total = cur.fetchone()[0]
    
    # Get paginated data
    columns = [
        'id', 'url', 'domain', 'online', 'http_status_code',
        'country', 'asn_name', 'ssl_enabled', 'cert_issuer',
        'registrar', 'threat_type', 'target_brand',
        'first_seen', 'last_checked'
    ]
    
    query = f"""
        SELECT {', '.join(columns)}
        FROM enriched_threats
        WHERE {where_clause}
        ORDER BY {order_by}
        LIMIT ? OFFSET ?
    """
    
    cur.execute(query, params + [limit, offset])
    rows = cur.fetchall()
    
    # Convert to DataFrame
    data = []
    for row in rows:
        data.append({col: row[col] for col in columns})
    
    df = pd.DataFrame(data)
    
    cur.close()
    return df, total


@st.cache_data(ttl=60)
def get_row_details(row_id: int) -> Optional[Dict[str, Any]]:
    """Get full details for a single row by ID."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(
        "SELECT * FROM enriched_threats WHERE id = ?",
        (row_id,)
    )
    row = cur.fetchone()
    cur.close()
    
    if not row:
        return None
    
    # Convert to dict and calculate derived fields
    details = dict(row)
    
    # Calculate domain age in days
    if details.get('creation_date'):
        try:
            creation_dt = datetime.fromisoformat(
                details['creation_date'].replace('Z', '+00:00')
            )
            age_days = (datetime.now(timezone.utc) - creation_dt).days
            details['domain_age_days'] = age_days
        except (ValueError, AttributeError):
            details['domain_age_days'] = None
    else:
        details['domain_age_days'] = None
    
    # Calculate cert expiry days
    if details.get('cert_valid_to'):
        try:
            # Handle SSL cert date format (e.g., "Dec 31 23:59:59 2024 GMT")
            cert_to_str = details['cert_valid_to'].replace(' GMT', '')
            cert_to_dt = datetime.strptime(cert_to_str, "%b %d %H:%M:%S %Y")
            cert_to_dt = cert_to_dt.replace(tzinfo=timezone.utc)
            days_to_expiry = (cert_to_dt - datetime.now(timezone.utc)).days
            details['cert_days_to_expiry'] = days_to_expiry
        except (ValueError, AttributeError):
            details['cert_days_to_expiry'] = None
    else:
        details['cert_days_to_expiry'] = None
    
    return details


@st.cache_data(ttl=60)
def get_map_points(
    where_clause: str,
    params: List[Any],
    limit: int = MAX_MAP_POINTS
) -> pd.DataFrame:
    """Get latitude/longitude points for map visualization."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    query = f"""
        SELECT latitude, longitude, country, domain, threat_type
        FROM enriched_threats
        WHERE {where_clause}
            AND latitude IS NOT NULL
            AND longitude IS NOT NULL
        LIMIT ?
    """
    
    cur.execute(query, params + [limit])
    rows = cur.fetchall()
    
    data = []
    for row in rows:
        data.append({
            'lat': row['latitude'],
            'lon': row['longitude'],
            'country': row['country'],
            'domain': row['domain'],
            'threat_type': row['threat_type']
        })
    
    df = pd.DataFrame(data)
    cur.close()
    return df


@st.cache_data(ttl=60)
def export_to_csv(
    where_clause: str,
    params: List[Any],
    limit: int = MAX_EXPORT_ROWS
) -> str:
    """Export filtered results to CSV string."""
    conn = get_db_connection()
    
    query = f"""
        SELECT *
        FROM enriched_threats
        WHERE {where_clause}
        LIMIT ?
    """
    
    df = pd.read_sql_query(query, conn, params=params + [limit])
    csv_str = df.to_csv(index=False)
    
    return csv_str


@st.cache_data(ttl=60)
def export_to_stix(
    where_clause: str,
    params: List[Any],
    limit: int = MAX_EXPORT_ROWS
) -> str:
    """Export filtered results to STIX 2.1 JSON format."""
    import json
    from datetime import datetime, timezone
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    query = f"""
        SELECT url, domain, ip_address, country, asn, asn_name,
               threat_type, target_brand, first_seen, source_feed,
               online, ssl_enabled
        FROM enriched_threats
        WHERE {where_clause}
        LIMIT ?
    """
    
    cur.execute(query, params + [limit])
    rows = cur.fetchall()
    cur.close()
    
    # Create STIX bundle
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{datetime.now(timezone.utc).isoformat()}",
        "objects": []
    }
    
    # Add identity object for the source
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--threat-intel-dashboard",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": "Threat Intelligence Dashboard",
        "identity_class": "system"
    }
    stix_bundle["objects"].append(identity)
    
    # Convert each threat to STIX indicator
    for row in rows:
        row_dict = dict(row)
        
        # Skip if no URL
        if not row_dict.get('url'):
            continue
        
        # Create indicator object
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hash(row_dict['url'])}",
            "created": row_dict.get('first_seen') or
            datetime.now(timezone.utc).isoformat(),
            "modified": row_dict.get('first_seen') or
            datetime.now(timezone.utc).isoformat(),
            "name": f"Phishing URL: {row_dict.get('domain', 'Unknown')}",
            "description": f"Malicious URL detected by "
            f"{row_dict.get('source_feed', 'Unknown')}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{row_dict['url']}']",
            "pattern_type": "stix",
            "valid_from": row_dict.get('first_seen') or
            datetime.now(timezone.utc).isoformat(),
        }
        
        # Add labels
        labels = []
        if row_dict.get('threat_type'):
            labels.append(row_dict['threat_type'])
        if row_dict.get('target_brand'):
            labels.append(f"targets-{row_dict['target_brand']}")
        if row_dict.get('online') == 'yes':
            labels.append('active')
        if labels:
            indicator["labels"] = labels
        
        # Add custom properties with additional context
        if row_dict.get('ip_address'):
            indicator["x_ip_address"] = row_dict['ip_address']
        if row_dict.get('country'):
            indicator["x_country"] = row_dict['country']
        if row_dict.get('asn'):
            indicator["x_asn"] = row_dict['asn']
        if row_dict.get('asn_name'):
            indicator["x_asn_name"] = row_dict['asn_name']
        if row_dict.get('ssl_enabled'):
            indicator["x_ssl_enabled"] = row_dict['ssl_enabled']
        
        stix_bundle["objects"].append(indicator)
    
    return json.dumps(stix_bundle, indent=2)


@st.cache_data(ttl=300)
def get_analytics_data() -> Dict[str, pd.DataFrame]:
    """Get data for analytics visualizations."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    analytics = {}
    
    # Threats by source feed
    cur.execute("""
        SELECT source_feed, COUNT(*) as count
        FROM enriched_threats
        WHERE source_feed IS NOT NULL
        GROUP BY source_feed
        ORDER BY count DESC
    """)
    analytics['by_source'] = pd.DataFrame(
        cur.fetchall(), columns=['source', 'count']
    )
    
    # Threats by country (top 15)
    cur.execute("""
        SELECT country, country_name, COUNT(*) as count
        FROM enriched_threats
        WHERE country IS NOT NULL
        GROUP BY country, country_name
        ORDER BY count DESC
        LIMIT 15
    """)
    analytics['by_country'] = pd.DataFrame(
        cur.fetchall(), columns=['code', 'country', 'count']
    )
    
    # Threats by threat type
    cur.execute("""
        SELECT threat_type, COUNT(*) as count
        FROM enriched_threats
        WHERE threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY count DESC
    """)
    analytics['by_type'] = pd.DataFrame(
        cur.fetchall(), columns=['type', 'count']
    )
    
    # Online status distribution
    cur.execute("""
        SELECT 
            CASE 
                WHEN online = 'yes' THEN 'Online'
                WHEN online = 'no' THEN 'Offline'
                ELSE 'Unknown'
            END as status,
            COUNT(*) as count
        FROM enriched_threats
        GROUP BY status
    """)
    analytics['by_status'] = pd.DataFrame(
        cur.fetchall(), columns=['status', 'count']
    )
    
    # SSL status distribution
    cur.execute("""
        SELECT 
            CASE 
                WHEN ssl_enabled = 'yes' THEN 'SSL Enabled'
                WHEN ssl_enabled = 'no' THEN 'No SSL'
                ELSE 'Unknown'
            END as status,
            COUNT(*) as count
        FROM enriched_threats
        GROUP BY status
    """)
    analytics['by_ssl'] = pd.DataFrame(
        cur.fetchall(), columns=['status', 'count']
    )
    
    # Threats over time (last 30 days)
    cur.execute("""
        SELECT 
            DATE(first_seen) as date,
            COUNT(*) as count
        FROM enriched_threats
        WHERE first_seen >= date('now', '-30 days')
        GROUP BY DATE(first_seen)
        ORDER BY date
    """)
    analytics['timeline'] = pd.DataFrame(
        cur.fetchall(), columns=['date', 'count']
    )
    
    # Top target brands (top 10)
    cur.execute("""
        SELECT target_brand, COUNT(*) as count
        FROM enriched_threats
        WHERE target_brand IS NOT NULL
        GROUP BY target_brand
        ORDER BY count DESC
        LIMIT 10
    """)
    analytics['by_brand'] = pd.DataFrame(
        cur.fetchall(), columns=['brand', 'count']
    )
    
    # Top ASNs (top 10)
    cur.execute("""
        SELECT asn_name, COUNT(*) as count
        FROM enriched_threats
        WHERE asn_name IS NOT NULL
        GROUP BY asn_name
        ORDER BY count DESC
        LIMIT 10
    """)
    analytics['by_asn'] = pd.DataFrame(
        cur.fetchall(), columns=['asn', 'count']
    )
    
    # Domain age distribution
    cur.execute("""
        SELECT 
            CASE 
                WHEN julianday('now') - julianday(creation_date) <= 30 
                    THEN '0-30 days'
                WHEN julianday('now') - julianday(creation_date) <= 90 
                    THEN '31-90 days'
                WHEN julianday('now') - julianday(creation_date) <= 180 
                    THEN '91-180 days'
                WHEN julianday('now') - julianday(creation_date) <= 365 
                    THEN '181-365 days'
                ELSE '1+ years'
            END as age_bucket,
            COUNT(*) as count
        FROM enriched_threats
        WHERE creation_date IS NOT NULL
        GROUP BY age_bucket
        ORDER BY 
            CASE age_bucket
                WHEN '0-30 days' THEN 1
                WHEN '31-90 days' THEN 2
                WHEN '91-180 days' THEN 3
                WHEN '181-365 days' THEN 4
                ELSE 5
            END
    """)
    analytics['by_age'] = pd.DataFrame(
        cur.fetchall(), columns=['age', 'count']
    )
    
    cur.close()
    return analytics


# ============================================================================
# UI Components
# ============================================================================

def render_sidebar_filters() -> Dict[str, Any]:
    """Render sidebar filters and return selected values."""
    st.sidebar.title("Filters")
    
    filters = {}
    
    # Get available options
    options = get_filter_options()
    
    # Text search
    filters['text_search'] = st.sidebar.text_input(
        "Search",
        placeholder="URL, domain, or IP address",
        help="Search across URL, domain, and IP address fields"
    )
    
    st.sidebar.markdown("---")
    
    # Multi-select filters
    filters['source_feeds'] = st.sidebar.multiselect(
        "Source Feed",
        options=options['source_feeds'],
        help="Filter by threat feed source"
    )
    
    filters['threat_types'] = st.sidebar.multiselect(
        "Threat Type",
        options=options['threat_types'],
        help="Filter by threat classification"
    )
    
    filters['target_brands'] = st.sidebar.multiselect(
        "Target Brand",
        options=options['target_brands'],
        help="Filter by targeted organization/brand"
    )
    
    filters['countries'] = st.sidebar.multiselect(
        "Country",
        options=options['countries'],
        help="Filter by hosting country"
    )
    
    st.sidebar.markdown("---")
    
    # Online status radio
    filters['online_status'] = st.sidebar.radio(
        "Online Status",
        options=['All', 'Yes', 'No', 'Unknown'],
        help="Filter by site availability"
    )
    
    st.sidebar.markdown("---")
    
    # Date range
    st.sidebar.subheader("First Seen Date Range")
    col1, col2 = st.sidebar.columns(2)
    with col1:
        filters['date_from'] = st.date_input(
            "From",
            value=None,
            help="Start date (inclusive)"
        )
    with col2:
        filters['date_to'] = st.date_input(
            "To",
            value=None,
            help="End date (inclusive)"
        )
    
    st.sidebar.markdown("---")
    
    # Advanced filters
    st.sidebar.subheader("Advanced Filters")
    
    filters['ssl_expiring_soon'] = st.sidebar.checkbox(
        "SSL Expiring <30 Days",
        help="Show only sites with SSL certificates expiring in the next 30 days"
    )
    
    filters['domain_age_buckets'] = st.sidebar.multiselect(
        "Domain Age",
        options=[
            ('new', '≤ 30 days'),
            ('medium', '31-180 days'),
            ('old', '> 180 days')
        ],
        format_func=lambda x: x[1],
        help="Filter by domain registration age"
    )
    # Extract just the keys
    if filters['domain_age_buckets']:
        filters['domain_age_buckets'] = [x[0] for x in filters['domain_age_buckets']]
    
    return filters


def render_kpis(stats: Dict[str, Any]):
    """Render KPI metrics at the top of the page."""
    st.markdown("### Key Metrics")
    
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
    
    with col3:
        st.metric(
            label="Currently Online",
            value=f"{stats['online']:,}",
            delta=f"{100*stats['online']/max(stats['total'], 1):.1f}%"
        )
    
    with col4:
        st.metric(
            label="Top Source",
            value=stats['top_source'],
            delta=f"{stats['top_source_count']:,} threats"
        )
    
    st.markdown("---")


def render_main_table(df: pd.DataFrame, total: int, page: int, page_size: int):
    """Render main data table with pagination."""
    st.markdown("### Threat Intelligence Table")
    
    if df.empty:
        st.info("No results found. Try adjusting your filters.")
        return
    
    # Show current page info
    start_idx = page * page_size + 1
    end_idx = min((page + 1) * page_size, total)
    st.caption(f"Showing {start_idx:,} - {end_idx:,} of {total:,} threats")
    
    # Format DataFrame for display
    display_df = df.copy()
    
    # Shorten URLs for display
    if 'url' in display_df.columns:
        display_df['url'] = display_df['url'].apply(
            lambda x: x[:60] + '...' if isinstance(x, str) and len(x) > 60 else x
        )
    
    # Format dates
    for col in ['first_seen', 'last_checked']:
        if col in display_df.columns:
            display_df[col] = pd.to_datetime(
                display_df[col], errors='coerce'
            ).dt.strftime('%Y-%m-%d %H:%M')
    
    # Format online status
    if 'online' in display_df.columns:
        display_df['online'] = display_df['online'].apply(
            lambda x: 'Yes' if x == 'yes' else 'No' if x == 'no' else 'Unknown'
        )
    
    # Format SSL status
    if 'ssl_enabled' in display_df.columns:
        display_df['ssl_enabled'] = display_df['ssl_enabled'].apply(
            lambda x: 'Yes' if x == 'yes' else 'No' if x == 'no' else 'Unknown'
        )
    
    # Display table
    st.dataframe(
        display_df.drop('id', axis=1, errors='ignore'),
        use_container_width=True,
        hide_index=True
    )
    
    # Pagination controls
    total_pages = (total + page_size - 1) // page_size
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        if page > 0:
            if st.button("← Previous", use_container_width=True):
                st.session_state.page = page - 1
                st.rerun()
    
    with col2:
        st.markdown(
            f"<div style='text-align: center; padding: 8px;'>"
            f"Page {page + 1} of {total_pages:,}</div>",
            unsafe_allow_html=True
        )
    
    with col3:
        if page < total_pages - 1:
            if st.button("Next →", use_container_width=True):
                st.session_state.page = page + 1
                st.rerun()
    
    # Row details expander
    st.markdown("---")
    st.markdown("### Threat Details")
    
    # Select row to view details
    row_ids = df['id'].tolist()
    row_labels = [
        f"ID {row_id} - {df[df['id']==row_id]['domain'].iloc[0]}"
        for row_id in row_ids
    ]
    
    selected_label = st.selectbox(
        "Select a threat to view full details:",
        options=[''] + row_labels,
        help="Choose a row to see all available fields"
    )
    
    if selected_label:
        selected_id = int(selected_label.split(' - ')[0].replace('ID ', ''))
        details = get_row_details(selected_id)
        
        if details:
            with st.expander("Full Record Details", expanded=True):
                render_detail_view(details)


def render_detail_view(details: Dict[str, Any]):
    """Render detailed view of a single threat record."""
    
    # Use threat ID as unique key prefix
    threat_id = details.get('id', hash(details.get('url', '')))
    
    # Basic Information
    st.markdown("#### Basic Information")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("URL", value=details.get('url', 'N/A'), 
                      disabled=True, key=f"url_{threat_id}")
        st.text_input("Domain", value=details.get('domain', 'N/A'), 
                      disabled=True, key=f"domain_{threat_id}")
        st.text_input("TLD", value=details.get('tld', 'N/A'), 
                      disabled=True, key=f"tld_{threat_id}")
    
    with col2:
        st.text_input("IP Address", value=details.get('ip_address', 'N/A'), 
                      disabled=True, key=f"ip_{threat_id}")
        online = details.get('online', 'unknown')
        if online == 'yes':
            online_display = 'Yes'
        elif online == 'no':
            online_display = 'No'
        else:
            online_display = 'Unknown'
        st.text_input("Online Status", value=online_display, 
                      disabled=True, key=f"online_{threat_id}")
        st.text_input("HTTP Status", 
                      value=str(details.get('http_status_code', 'N/A')), 
                      disabled=True, key=f"http_{threat_id}")
    
    st.markdown("---")
    
    # Network Information
    st.markdown("#### Network & Geographic Information")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("Country", 
                      value=details.get('country_name', 
                                       details.get('country', 'N/A')), 
                      disabled=True, key=f"country_{threat_id}")
        st.text_input("Region", value=details.get('region', 'N/A'), 
                      disabled=True, key=f"region_{threat_id}")
        st.text_input("City", value=details.get('city', 'N/A'), 
                      disabled=True, key=f"city_{threat_id}")
        coords = 'N/A'
        if details.get('latitude') and details.get('longitude'):
            coords = f"{details['latitude']:.4f}, {details['longitude']:.4f}"
        st.text_input("Coordinates", value=coords, 
                      disabled=True, key=f"coords_{threat_id}")
    
    with col2:
        st.text_input("ASN", value=str(details.get('asn', 'N/A')), 
                      disabled=True, key=f"asn_{threat_id}")
        st.text_input("ASN Name", value=details.get('asn_name', 'N/A'), 
                      disabled=True, key=f"asn_name_{threat_id}")
        st.text_input("ISP", value=details.get('isp', 'N/A'), 
                      disabled=True, key=f"isp_{threat_id}")
        st.text_input("CIDR Block", value=details.get('cidr_block', 'N/A'), 
                      disabled=True, key=f"cidr_{threat_id}")
    
    st.markdown("---")
    
    # SSL/TLS Information
    st.markdown("#### SSL/TLS Information")
    col1, col2 = st.columns(2)
    
    with col1:
        ssl_enabled = details.get('ssl_enabled', 'unknown')
        if ssl_enabled == 'yes':
            ssl_display = 'Enabled'
        elif ssl_enabled == 'no':
            ssl_display = 'Disabled'
        else:
            ssl_display = 'Unknown'
        st.text_input("SSL Status", value=ssl_display, 
                      disabled=True, key=f"ssl_{threat_id}")
        st.text_input("Cert Issuer", value=details.get('cert_issuer', 'N/A'), 
                      disabled=True, key=f"cert_issuer_{threat_id}")
        st.text_input("Cert Subject", value=details.get('cert_subject', 'N/A'), 
                      disabled=True, key=f"cert_subject_{threat_id}")
    
    with col2:
        st.text_input("Cert Valid From", 
                      value=details.get('cert_valid_from', 'N/A'), 
                      disabled=True, key=f"cert_from_{threat_id}")
        st.text_input("Cert Valid To", 
                      value=details.get('cert_valid_to', 'N/A'), 
                      disabled=True, key=f"cert_to_{threat_id}")
        expiry_days = details.get('cert_days_to_expiry')
        if expiry_days is not None:
            expiry_str = f"{expiry_days} days"
        else:
            expiry_str = 'N/A'
        if expiry_days is not None and expiry_days < 30 and expiry_days > 0:
            expiry_str += " (Expiring Soon)"
        elif expiry_days is not None and expiry_days <= 0:
            expiry_str += " (Expired)"
        st.text_input("Days to Expiry", value=expiry_str, 
                      disabled=True, key=f"cert_expiry_{threat_id}")
    
    st.markdown("---")
    
    # Domain Registration
    st.markdown("#### Domain Registration")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("Registrar", value=details.get('registrar', 'N/A'), 
                      disabled=True, key=f"registrar_{threat_id}")
        st.text_input("Creation Date", 
                      value=details.get('creation_date', 'N/A'), 
                      disabled=True, key=f"creation_{threat_id}")
        domain_age = details.get('domain_age_days')
        age_str = f"{domain_age} days" if domain_age is not None else 'N/A'
        if domain_age is not None and domain_age <= 30:
            age_str += " (New Domain)"
        st.text_input("Domain Age", value=age_str, 
                      disabled=True, key=f"age_{threat_id}")
    
    with col2:
        st.text_input("Expiry Date", value=details.get('expiry_date', 'N/A'), 
                      disabled=True, key=f"expiry_{threat_id}")
        st.text_input("Updated Date", value=details.get('updated_date', 'N/A'), 
                      disabled=True, key=f"updated_{threat_id}")
        st.text_input("Name Servers", 
                      value=details.get('name_servers', 'N/A'), 
                      disabled=True, key=f"ns_{threat_id}")
    
    st.markdown("---")
    
    # Content & Threat Classification
    st.markdown("#### Content & Threat Classification")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("Threat Type", value=details.get('threat_type', 'N/A'), 
                      disabled=True, key=f"threat_type_{threat_id}")
        st.text_input("Target Brand", 
                      value=details.get('target_brand', 'N/A'), 
                      disabled=True, key=f"brand_{threat_id}")
        st.text_input("Threat Tags", value=details.get('threat_tags', 'N/A'), 
                      disabled=True, key=f"tags_{threat_id}")
    
    with col2:
        st.text_input("Page Language", 
                      value=details.get('page_language', 'N/A'), 
                      disabled=True, key=f"lang_{threat_id}")
        st.text_input("Page Title", value=details.get('page_title', 'N/A'), 
                      disabled=True, key=f"title_{threat_id}")
    
    st.markdown("---")
    
    # Source & Tracking
    st.markdown("#### Source & Tracking")
    col1, col2 = st.columns(2)
    
    with col1:
        st.text_input("Source Feed", value=details.get('source_feed', 'N/A'), 
                      disabled=True, key=f"source_{threat_id}")
        st.text_input("Source ID", value=details.get('source_id', 'N/A'), 
                      disabled=True, key=f"source_id_{threat_id}")
        st.text_input("First Seen", value=details.get('first_seen', 'N/A'), 
                      disabled=True, key=f"first_{threat_id}")
    
    with col2:
        st.text_input("Last Seen", value=details.get('last_seen', 'N/A'), 
                      disabled=True, key=f"last_{threat_id}")
        st.text_input("Last Checked", 
                      value=details.get('last_checked', 'N/A'), 
                      disabled=True, key=f"checked_{threat_id}")
        st.text_input("Created At", value=details.get('created_at', 'N/A'), 
                      disabled=True, key=f"created_{threat_id}")
    
    # Notes
    if details.get('notes'):
        st.markdown("---")
        st.markdown("#### Notes")
        st.text_area("", value=details['notes'], disabled=True, 
                     height=100, key=f"notes_{threat_id}")


def render_map(map_data: pd.DataFrame):
    """Render geographic map visualization."""
    st.markdown("### Geographic Distribution")
    
    if map_data.empty:
        st.info("No geographic data available for current filters.")
        return
    
    st.caption(f"Showing {len(map_data):,} threats with location data (max {MAX_MAP_POINTS:,})")
    
    # Use Streamlit's built-in map
    st.map(map_data, latitude='lat', longitude='lon', size=20)


def render_export_section(where_clause: str, params: List[Any], total: int):
    """Render export section with CSV and STIX format options."""
    st.markdown("### Export Data")
    
    export_count = min(total, MAX_EXPORT_ROWS)
    
    st.info(
        f"Export {export_count:,} filtered results "
        f"(limited to {MAX_EXPORT_ROWS:,} rows)"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### CSV Format")
        st.caption("Standard CSV file for spreadsheets")
        if st.button("Generate CSV", key="csv_btn", use_container_width=True):
            with st.spinner("Generating CSV..."):
                csv_data = export_to_csv(where_clause, params, MAX_EXPORT_ROWS)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"threat_intel_export_{timestamp}.csv"
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=filename,
                    mime='text/csv',
                    use_container_width=True
                )
                st.success(f"CSV ready ({len(csv_data):,} bytes)")
    
    with col2:
        st.markdown("#### STIX 2.1 Format")
        st.caption("Structured Threat Information eXpression")
        if st.button("Generate STIX", key="stix_btn",
                     use_container_width=True):
            with st.spinner("Generating STIX bundle..."):
                stix_data = export_to_stix(where_clause, params,
                                           MAX_EXPORT_ROWS)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"threat_intel_export_{timestamp}.json"
                st.download_button(
                    label="Download STIX JSON",
                    data=stix_data,
                    file_name=filename,
                    mime='application/json',
                    use_container_width=True
                )
                st.success(f"STIX bundle ready ({len(stix_data):,} bytes)")


# ============================================================================
# Page Renderers
# ============================================================================

def render_overview_page():
    """Render the overview dashboard page with key metrics and charts."""
    st.title("Threat Intelligence Overview")
    st.markdown("High-level summary of threat landscape")
    st.markdown("---")

    # Get analytics data
    analytics = get_analytics_data()
    where_clause, params = build_where_clause({})
    stats = get_stats(where_clause, params)

    # Top KPIs
    render_kpis(stats)

    st.markdown("---")

    # Charts row 1
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### � Threats by Source Feed")
        if not analytics['by_source'].empty:
            fig = px.pie(
                analytics['by_source'],
                values='count',
                names='source',
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=350, showlegend=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available")

    with col2:
        st.markdown("#### Online Status Distribution")
        if not analytics['by_status'].empty:
            colors = {
                'Online': '#2ecc71',
                'Offline': '#e74c3c',
                'Unknown': '#95a5a6'
            }
            fig = go.Figure(data=[go.Pie(
                labels=analytics['by_status']['status'],
                values=analytics['by_status']['count'],
                marker=dict(colors=[
                    colors.get(s, '#3498db')
                    for s in analytics['by_status']['status']
                ]),
                hole=0.4
            )])
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=350, showlegend=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available")

    st.markdown("---")

    # Charts row 2
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### SSL/TLS Status")
        if not analytics['by_ssl'].empty:
            colors = {
                'SSL Enabled': '#27ae60',
                'No SSL': '#e67e22',
                'Unknown': '#95a5a6'
            }
            fig = go.Figure(data=[go.Bar(
                x=analytics['by_ssl']['status'],
                y=analytics['by_ssl']['count'],
                marker=dict(color=[
                    colors.get(s, '#3498db')
                    for s in analytics['by_ssl']['status']
                ]),
                text=analytics['by_ssl']['count'],
                textposition='outside'
            )])
            fig.update_layout(
                height=350,
                showlegend=False,
                yaxis_title="Count",
                xaxis_title=""
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available")

    with col2:
        st.markdown("#### Top Target Brands")
        if not analytics['by_brand'].empty:
            fig = px.bar(
                analytics['by_brand'],
                x='count',
                y='brand',
                orientation='h',
                color='count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                height=350,
                showlegend=False,
                xaxis_title="Count",
                yaxis_title="",
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available")

    st.markdown("---")

    # Timeline chart (full width)
    st.markdown("#### Threat Detection Timeline (Last 30 Days)")
    if not analytics['timeline'].empty:
        fig = px.area(
            analytics['timeline'],
            x='date',
            y='count',
            color_discrete_sequence=['#3498db']
        )
        fig.update_layout(
            height=300,
            xaxis_title="Date",
            yaxis_title="Threats Detected",
            showlegend=False
        )
        fig.update_traces(
            fill='tozeroy',
            line=dict(width=2)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available")


def render_analytics_page():
    """Render detailed analytics page with more charts."""
    st.title("Threat Analytics")
    st.markdown("Deep dive into threat patterns and distributions")
    st.markdown("---")

    analytics = get_analytics_data()

    # Row 1: Geography
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("#### Top Countries by Threat Count")
        if not analytics['by_country'].empty:
            fig = px.bar(
                analytics['by_country'],
                x='count',
                y='country',
                orientation='h',
                color='count',
                color_continuous_scale='Plasma',
                hover_data=['code']
            )
            fig.update_layout(
                height=450,
                xaxis_title="Threat Count",
                yaxis_title="",
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No country data available")

    with col2:
        st.markdown("#### Geographic Map")
        where_clause, params = build_where_clause({})
        map_data = get_map_points(where_clause, params, limit=500)
        if not map_data.empty:
            st.map(map_data, latitude='lat', longitude='lon', size=20)
            st.caption(f"Showing {len(map_data):,} threats")
        else:
            st.info("No location data")

    st.markdown("---")

    # Row 2: Network analysis
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Top Autonomous Systems (ASN)")
        if not analytics['by_asn'].empty:
            fig = px.bar(
                analytics['by_asn'],
                x='count',
                y='asn',
                orientation='h',
                color='count',
                color_continuous_scale='Blues'
            )
            fig.update_layout(
                height=400,
                xaxis_title="Threat Count",
                yaxis_title="",
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No ASN data available")

    with col2:
        st.markdown("#### Domain Age Distribution")
        if not analytics['by_age'].empty:
            fig = px.bar(
                analytics['by_age'],
                x='age',
                y='count',
                color='count',
                color_continuous_scale='Viridis'
            )
            fig.update_layout(
                height=400,
                xaxis_title="Domain Age",
                yaxis_title="Count",
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No domain age data available")


def render_data_explorer_page():
    """Render data explorer page with table and filters."""
    st.title("Data Explorer")
    st.markdown("Browse and search threat intelligence data")
    st.markdown("---")

    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = 0

    # Render sidebar filters
    filters = render_sidebar_filters()

    # Build WHERE clause
    where_clause, params = build_where_clause(filters)

    # Get stats
    stats = get_stats(where_clause, params)

    # Quick stats bar
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Filtered Results", f"{stats['total']:,}")
    with col2:
        st.metric("Online", f"{stats['online']:,}")
    with col3:
        st.metric("New (7d)", f"{stats['new_7d']:,}")
    with col4:
        st.metric("Top Source", stats['top_source'])

    st.markdown("---")

    # Get paginated data
    page = st.session_state.page
    df, total = get_rows(
        where_clause, params,
        limit=ROWS_PER_PAGE,
        offset=page * ROWS_PER_PAGE
    )

    # Render main table
    render_main_table(df, total, page, ROWS_PER_PAGE)

    st.markdown("---")

    # Export section
    with st.expander("Export Data (CSV / STIX)", expanded=False):
        render_export_section(where_clause, params, total)


def render_search_page():
    """Render quick search page."""
    st.title("Threat Search")
    st.markdown("Quick lookup for specific threats")
    st.markdown("---")

    search_type = st.radio(
        "Search by:",
        options=['URL', 'Domain', 'IP Address', 'Threat ID'],
        horizontal=True
    )

    search_term = st.text_input(
        f"Enter {search_type}",
        placeholder=f"Type {search_type.lower()} here...",
        key="search_input"
    )

    if search_term:
        conn = get_db_connection()
        cur = conn.cursor()

        if search_type == 'URL':
            query = "SELECT * FROM enriched_threats WHERE url LIKE ? LIMIT 10"
            params = (f"%{search_term}%",)
        elif search_type == 'Domain':
            query = (
                "SELECT * FROM enriched_threats WHERE domain LIKE ? "
                "LIMIT 10"
            )
            params = (f"%{search_term}%",)
        elif search_type == 'IP Address':
            query = (
                "SELECT * FROM enriched_threats WHERE ip_address LIKE ? "
                "LIMIT 10"
            )
            params = (f"%{search_term}%",)
        else:  # Threat ID
            query = "SELECT * FROM enriched_threats WHERE id = ?"
            try:
                params = (int(search_term),)
            except ValueError:
                st.error("Threat ID must be a number")
                return

        cur.execute(query, params)
        results = cur.fetchall()
        cur.close()

        if results:
            st.success(f"Found {len(results)} result(s)")
            st.markdown("---")

            for result in results:
                details = dict(result)
                with st.expander(
                    f" {details.get('url', 'N/A')[:80]}...",
                    expanded=len(results) == 1
                ):
                    render_detail_view(details)
        else:
            st.warning(f"No results found for '{search_term}'")
    else:
        st.info("Enter a search term above to find threats")


# ============================================================================
# Main Application
# ============================================================================

def main():
    """Main application entry point with page navigation."""

    # Check database exists
    if not DB_PATH.exists():
        st.error(
            f"❌ Database not found at {DB_PATH}\n\n"
            "Please run the enrichment pipeline first:\n"
            "```bash\n"
            "python -m app.database.db  # Create schema\n"
            "python -m app.database.enrich  # Populate data\n"
            "```"
        )
        return

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page:",
        options=[
            "Overview",
            "Analytics",
            "Data Explorer",
            "Search"
        ],
        label_visibility="collapsed"
    )

    st.sidebar.markdown("---")

    # Route to appropriate page
    if page == "Overview":
        render_overview_page()
    elif page == "Analytics":
        render_analytics_page()
    elif page == "Data Explorer":
        render_data_explorer_page()
    elif page == "Search":
        render_search_page()

    # Footer
    st.sidebar.markdown("---")
    st.sidebar.caption("Threat Intelligence Dashboard")
    st.sidebar.caption(f"Database: {DB_PATH.name}")


if __name__ == "__main__":
    main()
