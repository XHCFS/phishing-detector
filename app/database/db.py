#!/usr/bin/env python3
"""
Create enriched threat feeds database (threat_feeds.db).

This database contains a single enriched table with fields from raw
threat feeds plus additional fields that can be populated via WHOIS,
GeoIP, and similar lookups.

Fields include:
- Basic threat data (URL, Domain, IP, Online status)
- Network information (CIDR Block, ASN, ASN Name, ISP)
- Geographic data (Country, Region, City)
- SSL/TLS information (SSL status, Certificate Issuer, Validity)
- Domain registration (Registrar, Creation Date, Expiry Date, TLD)
- Content metadata (Page Language, HTTP Status)
- Source tracking (Source Feed, First Seen, Last Seen)
"""

import sqlite3
from pathlib import Path
from . import rawdb
from . import grabrawdata

# Database path for enriched data
DB_PATH = Path(__file__).parent / "threat_feeds.db"

# DDL for the enriched threat feeds table
DDL = """
CREATE TABLE IF NOT EXISTS enriched_threats (
    -- Primary key and identifiers
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT,
    
    -- Status information
    online TEXT,                      -- 'yes', 'no', or NULL (unknown)
    http_status_code INTEGER,         -- HTTP status code from probe
    
    -- Network information (easily accessible via IP lookup)
    ip_address TEXT,
    cidr_block TEXT,                  -- CIDR block from WHOIS/IP lookup
    asn INTEGER,                      -- Autonomous System Number
    asn_name TEXT,                    -- AS organization name
    isp TEXT,                         -- Internet Service Provider name
    
    -- Geographic information (easily accessible via GeoIP)
    country TEXT,                     -- Country code (e.g., 'US', 'CN')
    country_name TEXT,                -- Full country name
    region TEXT,                      -- State/province/region
    city TEXT,                        -- City name
    latitude REAL,                    -- Geographic coordinates
    longitude REAL,
    
    -- SSL/TLS information (from SSL cert inspection)
    ssl_enabled TEXT,                 -- 'yes', 'no', or NULL
    cert_issuer TEXT,                 -- SSL certificate issuer
    cert_subject TEXT,                -- SSL certificate subject
    cert_valid_from TEXT,             -- Certificate validity start date
    cert_valid_to TEXT,               -- Certificate validity end date
    cert_serial TEXT,                 -- Certificate serial number
    
    -- Domain WHOIS information (easily accessible via WHOIS lookup)
    tld TEXT,                         -- Top-level domain (.com, .net, etc.)
    registrar TEXT,                   -- Domain registrar name
    creation_date TEXT,               -- Domain creation/registration date
    expiry_date TEXT,                 -- Domain expiration date
    updated_date TEXT,                -- Last WHOIS update date
    name_servers TEXT,                -- Name servers (comma-separated)
    
    -- Content metadata
    page_language TEXT,               -- Detected page language
    page_title TEXT,                  -- Page title from HTML
    
    -- Threat categorization
    threat_type TEXT,                 -- Type of threat (phishing, etc.)
    target_brand TEXT,                -- Targeted brand/organization
    threat_tags TEXT,                 -- Comma-separated tags
    
    -- Source and tracking
    source_feed TEXT NOT NULL,        -- Source feed name
    source_id TEXT,                   -- Original ID from source feed
    first_seen DATETIME DEFAULT (datetime('now')),
    last_seen DATETIME,
    last_checked DATETIME,            -- Last time enrichment was attempted
    
    -- Additional notes
    notes TEXT,                       -- Any additional information
    
    -- Risk scoring
    risk_score INTEGER DEFAULT 0,    -- Calculated risk score (0-100)
    
    -- Timestamps
    created_at DATETIME DEFAULT (datetime('now')),
    updated_at DATETIME DEFAULT (datetime('now'))
);

-- Indexes for common queries and lookups
CREATE INDEX IF NOT EXISTS idx_enriched_domain
    ON enriched_threats(domain);
CREATE INDEX IF NOT EXISTS idx_enriched_ip
    ON enriched_threats(ip_address);
CREATE INDEX IF NOT EXISTS idx_enriched_asn
    ON enriched_threats(asn);
CREATE INDEX IF NOT EXISTS idx_enriched_country
    ON enriched_threats(country);
CREATE INDEX IF NOT EXISTS idx_enriched_source
    ON enriched_threats(source_feed);
CREATE INDEX IF NOT EXISTS idx_enriched_online
    ON enriched_threats(online);
CREATE INDEX IF NOT EXISTS idx_enriched_tld
    ON enriched_threats(tld);
CREATE INDEX IF NOT EXISTS idx_enriched_threat_type
    ON enriched_threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_enriched_first_seen
    ON enriched_threats(first_seen);
CREATE INDEX IF NOT EXISTS idx_enriched_last_seen
    ON enriched_threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_enriched_risk_score
    ON enriched_threats(risk_score);
"""


def calculate_risk_scores(path: Path = DB_PATH):
    """
    Calculate and update risk scores for all threats in the database.
    Risk score components:
    1. Liveness (0-35 pts) - based on HTTP status and online status
    2. Recency (0-25 pts) - based on days since last_seen
    3. Domain age (0-20 pts) - based on days since creation_date
    4. TLD/Platform (0-10 pts) - based on TLD and hosting platform
    5. URL keywords (0-10 pts) - based on suspicious keywords in URL
    """
    con = sqlite3.connect(str(path))
    
    # SQL to calculate risk scores
    risk_calculation_sql = """
    UPDATE enriched_threats 
    SET risk_score = (
        -- 1) Liveness Score (0-35 pts)
        CASE 
            -- HTTP status codes take priority
            WHEN http_status_code IN (200, 301, 302, 307, 308) THEN 35
            WHEN http_status_code IN (401, 403, 405, 429, 451) THEN 28
            WHEN http_status_code >= 500 AND http_status_code < 600 THEN 20
            WHEN http_status_code IN (404, 410) THEN 12
            WHEN http_status_code IS NOT NULL THEN 10  -- Other codes
            
            -- Fall back to online status if no HTTP code
            WHEN online = 'yes' THEN 20
            WHEN online = 'no' OR online IS NULL THEN 10
            ELSE 10
        END
        
        +
        
        -- 2) Recency Score (0-25 pts) - days since last_seen
        CASE 
            WHEN last_seen IS NULL THEN 5
            WHEN julianday('now') - julianday(last_seen) <= 3 THEN 25
            WHEN julianday('now') - julianday(last_seen) <= 7 THEN 20
            WHEN julianday('now') - julianday(last_seen) <= 14 THEN 15
            WHEN julianday('now') - julianday(last_seen) <= 30 THEN 10
            ELSE 5
        END
        
        +
        
        -- 3) Domain Age Score (0-20 pts) - days since creation_date
        CASE 
            WHEN creation_date IS NULL THEN 8
            WHEN julianday('now') - julianday(creation_date) <= 7 THEN 20
            WHEN julianday('now') - julianday(creation_date) <= 30 THEN 15
            WHEN julianday('now') - julianday(creation_date) <= 90 THEN 10
            ELSE 5
        END
        
        +
        
        -- 4) TLD/Platform Score (0-10 pts)
        CASE
            -- High-risk TLDs
            WHEN LOWER(tld) IN ('zip', 'mov', 'top', 'cc', 'icu', 'xyz', 'click', 'info') THEN 
                CASE 
                    -- Check for ephemeral hosting platforms (+3, cap at 10)
                    WHEN LOWER(url) LIKE '%.vercel.app%' OR
                         LOWER(url) LIKE '%.web.app%' OR
                         LOWER(url) LIKE '%.github.io%' OR
                         LOWER(url) LIKE '%.cprapid.com%' OR
                         LOWER(url) LIKE '%.pages.dev%' OR
                         LOWER(url) LIKE '%.netlify.app%' OR
                         LOWER(url) LIKE '%.render.com%' OR
                         LOWER(url) LIKE '%.fly.dev%' THEN 10  -- 10 + 3 = 13, but capped at 10
                    ELSE 10
                END
                
            -- Common TLDs
            WHEN LOWER(tld) IN ('com', 'net', 'org') THEN
                CASE 
                    -- Check for ephemeral hosting platforms (+3)
                    WHEN LOWER(url) LIKE '%.vercel.app%' OR
                         LOWER(url) LIKE '%.web.app%' OR
                         LOWER(url) LIKE '%.github.io%' OR
                         LOWER(url) LIKE '%.cprapid.com%' OR
                         LOWER(url) LIKE '%.pages.dev%' OR
                         LOWER(url) LIKE '%.netlify.app%' OR
                         LOWER(url) LIKE '%.render.com%' OR
                         LOWER(url) LIKE '%.fly.dev%' THEN 8  -- 5 + 3 = 8
                    ELSE 5
                END
                
            -- Other TLDs
            ELSE 
                CASE 
                    -- Check for ephemeral hosting platforms (+3, cap at 10)
                    WHEN LOWER(url) LIKE '%.vercel.app%' OR
                         LOWER(url) LIKE '%.web.app%' OR
                         LOWER(url) LIKE '%.github.io%' OR
                         LOWER(url) LIKE '%.cprapid.com%' OR
                         LOWER(url) LIKE '%.pages.dev%' OR
                         LOWER(url) LIKE '%.netlify.app%' OR
                         LOWER(url) LIKE '%.render.com%' OR
                         LOWER(url) LIKE '%.fly.dev%' THEN 10  -- 7 + 3 = 10
                    ELSE 7
                END
        END
        
        +
        
        -- 5) URL Keywords Score (0-10 pts)
        CASE 
            WHEN LOWER(url) LIKE '%login%' OR
                 LOWER(url) LIKE '%verify%' OR
                 LOWER(url) LIKE '%secure%' OR
                 LOWER(url) LIKE '%update%' OR
                 LOWER(url) LIKE '%invoice%' OR
                 LOWER(url) LIKE '%mfa%' OR
                 LOWER(url) LIKE '%password%' OR
                 LOWER(url) LIKE '%wallet%' OR
                 LOWER(url) LIKE '%bank%' OR
                 LOWER(url) LIKE '%microsoft%' OR
                 LOWER(url) LIKE '%office365%' OR
                 LOWER(url) LIKE '%att%' THEN 10
            ELSE 0
        END
    );
    """
    
    print("Calculating risk scores for all threats...")
    con.execute(risk_calculation_sql)
    con.commit()
    
    # Get statistics
    stats = con.execute("""
        SELECT 
            MIN(risk_score) as min_score,
            MAX(risk_score) as max_score,
            ROUND(AVG(risk_score), 2) as avg_score,
            COUNT(*) as total_threats
        FROM enriched_threats
    """).fetchone()
    
    print(f"Risk scores calculated:")
    print(f"  Range: {stats[0]} - {stats[1]}")
    print(f"  Average: {stats[2]}")
    print(f"  Total threats: {stats[3]}")
    
    con.close()


def create_db(path: Path = DB_PATH):
    """
    Create the enriched threat feeds database with all necessary tables
    and indexes. This creates a single table for storing enriched
    phishing/malware threat data.
    """
    con = sqlite3.connect(str(path))
    
    # Check if table exists and needs risk_score column
    try:
        # Try to get the table schema
        schema = con.execute("PRAGMA table_info(enriched_threats)").fetchall()
        column_names = [col[1] for col in schema]
        
        if 'risk_score' not in column_names and schema:
            # Table exists but missing risk_score column - add it
            print("Adding risk_score column to existing table...")
            con.execute("ALTER TABLE enriched_threats ADD COLUMN risk_score INTEGER DEFAULT 0")
            con.execute("CREATE INDEX IF NOT EXISTS idx_enriched_risk_score ON enriched_threats(risk_score)")
            con.commit()
        else:
            # Create new table with full schema
            con.executescript(DDL)
            con.commit()
    except sqlite3.OperationalError:
        # Table doesn't exist - create it
        con.executescript(DDL)
        con.commit()
    
    con.close()
    print(f"Created/validated enriched database: {path.resolve()}")


def init_db():
    """
    Initialize both raw and enriched databases.
    1. Create raw threat feeds database
    2. Populate raw database with threat data
    3. Create enriched database schema
    4. Calculate risk scores for existing data
    
    Note: This only creates the databases. A separate enrichment process
    is needed to populate the enriched_threats table with WHOIS/GeoIP data.
    """
    # Create and populate raw database
    rawdb.create_db()
    grabrawdata.main()
    
    # Create enriched database schema
    create_db()
    
    # Calculate risk scores if there's existing data
    try:
        con = sqlite3.connect(str(DB_PATH))
        count = con.execute("SELECT COUNT(*) FROM enriched_threats").fetchone()[0]
        con.close()
        
        if count > 0:
            print(f"Found {count} existing threats, calculating risk scores...")
            calculate_risk_scores()
        else:
            print("No existing threats found. Risk scores will be calculated after enrichment.")
    except sqlite3.OperationalError:
        print("Database not yet populated. Risk scores will be calculated after enrichment.")


if __name__ == "__main__":
    create_db()

