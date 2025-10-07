#!/usr/bin/env python3
"""
Create an SQLite database with one table per requested feed/archival database:
- openphish_feed
- openphish_archival (when license is available)
- phishtank_archival
- urlhaus_api

Usage: run this script; it will create 'threat_feeds.db' in the current folder.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "threat_feeds_raw.db"

DDL = [
    # OpenPhish Feed (line separated domains/urls)
    """
    CREATE TABLE IF NOT EXISTS openphish_feed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        domain TEXT,
        added_at DATETIME DEFAULT (datetime('now')),
        note TEXT
    );
    """,

    # # OpenPhish Archival DB (fields from your spec)
    # """
    # CREATE TABLE IF NOT EXISTS openphish_archival (
    #     id INTEGER PRIMARY KEY AUTOINCREMENT,
    #     asn INTEGER,
    #     asn_name TEXT,
    #     brand TEXT,
    #     country_code TEXT,
    #     country_name TEXT,
    #     drop_accounts TEXT,        -- might be "yes"/"no" or JSON/text
    #     host TEXT,
    #     ip TEXT,
    #     isotime TEXT,              -- timestamp as ISO string
    #     page_language TEXT,
    #     sector TEXT,
    #     ssl_cert_issued_by TEXT,
    #     ssl_cert_issued_to TEXT,
    #     ssl_cert_serial TEXT,
    #     tld TEXT,
    #     url TEXT NOT NULL UNIQUE,
    #     url_norm TEXT,
    #     url_page TEXT,
    #     url_path TEXT,
    #     url_query_string TEXT,
    #     url_scheme TEXT,
    #     inserted_at DATETIME DEFAULT (datetime('now'))
    # );
    # """,

    # PhishTank Archival DB (fields from your spec)
    """
    CREATE TABLE IF NOT EXISTS phishtank_archival (
        phish_id INTEGER PRIMARY KEY,   -- phish_id from dataset
        url TEXT NOT NULL,
        phish_detail_url TEXT,
        submission_time TEXT,
        verified TEXT,                -- e.g., 'yes'/'no'
        verification_time TEXT,
        online TEXT,                  -- e.g., 'yes'/'no'
        target TEXT,
        ip_address TEXT,              -- from details array
        cidr_block TEXT,              -- from details array
        announcing_network TEXT,      -- from details array
        rir TEXT,                     -- from details array
        detail_time TEXT,             -- from details array
        inserted_at DATETIME DEFAULT (datetime('now'))
    );
    """,

    # URLhaus API table (fields from your spec, flexible)
    """
    CREATE TABLE IF NOT EXISTS urlhaus_api (
        urlhaus_id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        url_status TEXT,
        url_dateadded TEXT,
        url_lastseen TEXT,
        reporter TEXT,
        reporter_handle TEXT,
        verifier TEXT,
        threat TEXT,
        tags TEXT,              -- CSV/text list
        file_md5 TEXT,
        file_sha256 TEXT,
        file_name TEXT,
        file_size INTEGER,
        payload_type TEXT,
        distribution TEXT,
        asn INTEGER,
        country TEXT,
        referrer TEXT,
        request_headers TEXT,   -- raw headers (TEXT); can store JSON
        response_code INTEGER,
        cloaking TEXT,
        comments TEXT,
        inserted_at DATETIME DEFAULT (datetime('now'))
    );
    """,

    # Indexes for common lookups
    "CREATE INDEX IF NOT EXISTS idx_openphish_feed_domain ON openphish_feed(domain);",
    # "CREATE INDEX IF NOT EXISTS idx_openphish_archival_host ON openphish_archival(host);",
    # "CREATE INDEX IF NOT EXISTS idx_openphish_archival_ip ON openphish_archival(ip);",
    "CREATE INDEX IF NOT EXISTS idx_phishtank_url ON phishtank_archival(url);",
    "CREATE INDEX IF NOT EXISTS idx_phishtank_ip_address ON phishtank_archival(ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_phishtank_announcing_network ON phishtank_archival(announcing_network);",
    "CREATE INDEX IF NOT EXISTS idx_urlhaus_threat ON urlhaus_api(threat);",
    "CREATE INDEX IF NOT EXISTS idx_urlhaus_asn ON urlhaus_api(asn);",
]

def create_db(path: Path = DB_PATH):
    con = sqlite3.connect(str(path))
    cur = con.cursor()
    for stmt in DDL:
        cur.executescript(stmt) if ";" in stmt and stmt.strip().startswith("CREATE TABLE") else cur.execute(stmt)
    con.commit()
    cur.close()
    con.close()
    print(f"Created/validated database: {path.resolve()}")

if __name__ == "__main__":
    create_db()
