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
"""


def create_db(path: Path = DB_PATH):
    """
    Create the enriched threat feeds database with all necessary tables
    and indexes. This creates a single table for storing enriched
    phishing/malware threat data.
    """
    con = sqlite3.connect(str(path))
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
    
    Note: This only creates the databases. A separate enrichment process
    is needed to populate the enriched_threats table with WHOIS/GeoIP data.
    """
    # Create and populate raw database
    rawdb.create_db()
    grabrawdata.main()
    
    # Create enriched database schema
    create_db()


if __name__ == "__main__":
    create_db()

