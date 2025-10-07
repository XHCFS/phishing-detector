#!/usr/bin/env python3
"""
populate_threat_feeds.py (updated)

Populates 'threat_feeds.db' (or a provided --db path) from public feeds:
- OpenPhish Feed (free)
- PhishTank online-valid (free; stable origin -> redirects to signed CDN)
- URLhaus recent URLs (free; v1 API requires POST)

Idempotent: uses INSERT OR IGNORE / UPSERT. Safe to run multiple times/day.
Skips OpenPhish Archival (license required).
"""

import os
import io
import csv
import json
import time
import argparse
import sqlite3
from pathlib import Path
from urllib.parse import urlparse
from typing import Iterable, Dict, Any, Optional

import requests

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Note: python-dotenv not installed. Using system environment variables only.")
    print("Install with: pip install python-dotenv")

# ---------------------------
# Config
# ---------------------------
DB_PATH = Path("threat_feeds.db")
UA = {"User-Agent": "phish-grabber/1.1 (+local use)"}

# OpenPhish free feed (URLs; we extract domain)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# PhishTank free public feed (API key optional for higher limits)
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
if PHISHTANK_API_KEY:
    PHISHTANK_JSON_URL = f"https://data.phishtank.com/data/{PHISHTANK_API_KEY}/online-valid.json"
    print(f"Using PhishTank API key: {PHISHTANK_API_KEY[:8]}...")
else:
    PHISHTANK_JSON_URL = "https://data.phishtank.com/data/online-valid.json"
    print("Using PhishTank public endpoint (rate limited)")
    
# URLhaus v1 API (GET with Auth-Key header)
URLHAUS_RECENT_URLS = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "").strip()
if URLHAUS_API_KEY:
    print(f"Using URLhaus API key: {URLHAUS_API_KEY[:8]}...")
else:
    print("No URLhaus API key found - URLhaus data will be skipped")

# Retry only on transient statuses
RETRY_STATUSES = {429, 500, 502, 503, 504}


# ---------------------------
# DB helpers
# ---------------------------
def connect_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA foreign_keys=ON;")
    return con

def exec_many(con: sqlite3.Connection, sql: str, rows: Iterable[tuple]):
    cur = con.cursor()
    cur.executemany(sql, rows)
    con.commit()
    cur.close()

def ensure_schema(con: sqlite3.Connection):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS openphish_feed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        domain TEXT,
        added_at DATETIME DEFAULT (datetime('now')),
        note TEXT
    );
    CREATE TABLE IF NOT EXISTS phishtank_archival (
        phish_id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        phish_detail_url TEXT,
        submission_time TEXT,
        verified TEXT,
        verification_time TEXT,
        online TEXT,
        target TEXT,
        inserted_at DATETIME DEFAULT (datetime('now'))
    );
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
        tags TEXT,
        file_md5 TEXT,
        file_sha256 TEXT,
        file_name TEXT,
        file_size INTEGER,
        payload_type TEXT,
        distribution TEXT,
        asn INTEGER,
        country TEXT,
        referrer TEXT,
        request_headers TEXT,
        response_code INTEGER,
        cloaking TEXT,
        comments TEXT,
        inserted_at DATETIME DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_openphish_feed_domain ON openphish_feed(domain);
    CREATE INDEX IF NOT EXISTS idx_phishtank_url ON phishtank_archival(url);
    CREATE INDEX IF NOT EXISTS idx_urlhaus_threat ON urlhaus_api(threat);
    CREATE INDEX IF NOT EXISTS idx_urlhaus_asn ON urlhaus_api(asn);
    """)


# ---------------------------
# HTTP helpers
# ---------------------------
def http_get(url: str, timeout: int = 30, max_retries: int = 3, headers: Optional[dict] = None) -> requests.Response:
    backoff = 2
    for attempt in range(1, max_retries + 1):
        r = requests.get(url, timeout=timeout, headers=headers or UA, allow_redirects=True)
        if r.status_code == 200:
            return r
        if r.status_code in RETRY_STATUSES:
            if attempt == max_retries:
                r.raise_for_status()
            time.sleep(min(backoff, 20))
            backoff *= 2
            continue
        # fail fast on other 4xx/5xx
        r.raise_for_status()
    raise RuntimeError(f"Failed GET {url}")

def http_post(url: str, timeout: int = 30, max_retries: int = 3, headers: Optional[dict] = None, json_body: Optional[dict] = None) -> requests.Response:
    backoff = 2
    for attempt in range(1, max_retries + 1):
        r = requests.post(url, timeout=timeout, headers=headers or UA, json=json_body)
        if r.status_code == 200:
            return r
        if r.status_code in RETRY_STATUSES:
            if attempt == max_retries:
                r.raise_for_status()
            time.sleep(min(backoff, 20))
            backoff *= 2
            continue
        r.raise_for_status()
    raise RuntimeError(f"Failed POST {url}")


# ---------------------------
# Loaders
# ---------------------------
def extract_domain(u: str) -> Optional[str]:
    try:
        p = urlparse(u.strip())
        return p.hostname
    except Exception:
        return None

def load_openphish_feed(con: sqlite3.Connection, url: str = OPENPHISH_FEED_URL) -> int:
    r = http_get(url)
    items = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
    rows = [(u, extract_domain(u)) for u in items]

    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM openphish_feed")
    before = cur.fetchone()[0]

    cur.executemany(
        "INSERT OR IGNORE INTO openphish_feed (url, domain) VALUES (?, ?)",
        rows
    )
    con.commit()

    cur.execute("SELECT COUNT(*) FROM openphish_feed")
    after = cur.fetchone()[0]
    cur.close()
    return after - before

def fetch_phishtank_json() -> list:
    # Try multiple PhishTank endpoints in order of preference
    urls_to_try = []
    
    # If we have an API key, try that endpoint first
    if PHISHTANK_API_KEY:
        urls_to_try.extend([
            f"https://data.phishtank.com/data/{PHISHTANK_API_KEY}/online-valid.json",
            f"https://data.phishtank.com/data/{PHISHTANK_API_KEY}/online-valid.csv",
        ])
    
    # Always include public endpoints as fallback
    urls_to_try.extend([
        "https://data.phishtank.com/data/online-valid.csv",  # CSV is more reliable
        "https://data.phishtank.com/data/online-valid.json.gz",  # Compressed JSON
        "https://data.phishtank.com/data/online-valid.json",  # Original JSON
    ])
    
    for url in urls_to_try:
        try:
            print(f"Trying PhishTank URL: {url}")
            r = requests.get(url, headers={"User-Agent": "phish-grabber/1.1"}, 
                           allow_redirects=True, timeout=30)
            if r.status_code == 200:
                if url.endswith('.csv'):
                    return parse_phishtank_csv(r.text)
                elif url.endswith('.gz'):
                    import gzip
                    import json
                    return json.loads(gzip.decompress(r.content).decode('utf-8'))
                else:
                    return r.json()
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            continue
    
    raise RuntimeError("All PhishTank endpoints failed")

def parse_phishtank_csv(csv_text: str) -> list:
    """Parse PhishTank CSV format into the same structure as JSON"""
    import csv
    import io
    
    reader = csv.DictReader(io.StringIO(csv_text))
    results = []
    for row in reader:
        results.append({
            'phish_id': row.get('phish_id'),
            'url': row.get('url'),
            'phish_detail_url': row.get('phish_detail_url'),
            'submission_time': row.get('submission_time'),
            'verified': row.get('verified'),
            'verification_time': row.get('verification_time'),
            'online': row.get('online'),
            'target': row.get('target', ''),
        })
    return results

def map_phishtank_json_obj(o: Dict[str, Any]) -> tuple:
    phish_id = int(o.get("phish_id")) if o.get("phish_id") not in (None, "") else None
    url = o.get("url")
    phish_detail_url = o.get("phish_detail_url")
    submission_time = o.get("submission_time")
    # Handle both boolean (JSON) and string (CSV) formats
    def yn(val):
        if val is True or val == "yes":
            return "yes"
        elif val is False or val == "no":
            return "no"
        else:
            return None
    verified = yn(o.get("verified"))
    verification_time = o.get("verification_time")
    online = yn(o.get("online"))
    target = o.get("target")
    return (phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target)

def load_phishtank_archival(con: sqlite3.Connection) -> int:
    data = fetch_phishtank_json()
    rows = [map_phishtank_json_obj(o) for o in data]
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM phishtank_archival"); before = cur.fetchone()[0]
    cur.executemany("""
      INSERT INTO phishtank_archival
      (phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target)
      VALUES (?,?,?,?,?,?,?,?)
      ON CONFLICT(phish_id) DO UPDATE SET
        url=excluded.url,
        phish_detail_url=excluded.phish_detail_url,
        submission_time=excluded.submission_time,
        verified=excluded.verified,
        verification_time=excluded.verification_time,
        online=excluded.online,
        target=excluded.target
    """, rows)
    con.commit()
    cur.execute("SELECT COUNT(*) FROM phishtank_archival"); after = cur.fetchone()[0]
    cur.close()
    return max(0, after - before)


def _safe_int(x) -> Optional[int]:
    try:
        return int(x) if x is not None and str(x).strip() != "" else None
    except Exception:
        return None

def _serialize_comments(c) -> Optional[str]:
    try:
        if c is None:
            return None
        if isinstance(c, str):
            return c
        return json.dumps(c, ensure_ascii=False)
    except Exception:
        return None

def load_urlhaus_recent(con: sqlite3.Connection) -> int:
    if not URLHAUS_API_KEY:
        print("Warning: URLHAUS_API_KEY environment variable not set. Skipping URLhaus.")
        return 0
    
    headers = {
        "User-Agent": "phish-grabber/1.1", 
        "Auth-Key": URLHAUS_API_KEY
    }
    r = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        headers=headers,
        timeout=30,
    )
    r.raise_for_status()
    obj = r.json()
    if obj.get("query_status") != "ok":
        return 0
    items = obj.get("urls", []) or []

    rows = []
    for it in items:
        rows.append((
            it.get("url"),
            it.get("url_status"),
            it.get("date_added") or it.get("url_dateadded"),
            it.get("lastseen") or it.get("url_lastseen"),
            it.get("reporter"),
            it.get("reporter_handle") or it.get("reporter"),
            None,  # verifier (not in recent endpoint)
            it.get("threat"),
            ",".join(it.get("tags", []) or []) if isinstance(it.get("tags"), list) else it.get("tags"),
            it.get("file_md5"),
            it.get("file_sha256"),
            it.get("filename") or it.get("file_name"),
            _safe_int(it.get("file_size")),
            it.get("payload_type"),
            it.get("distribution"),
            _safe_int(it.get("asn")),
            it.get("country"),
            it.get("reference") or it.get("referrer"),
            None,  # request_headers
            _safe_int(it.get("response_code")),
            it.get("cloaking"),
            _serialize_comments(it.get("comments")),
        ))

    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM urlhaus_api")
    before = cur.fetchone()[0]

    cur.executemany("""
        INSERT OR IGNORE INTO urlhaus_api
        (url, url_status, url_dateadded, url_lastseen, reporter, reporter_handle, verifier, threat, tags,
         file_md5, file_sha256, file_name, file_size, payload_type, distribution, asn, country, referrer,
         request_headers, response_code, cloaking, comments)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    con.commit()

    cur.execute("SELECT COUNT(*) FROM urlhaus_api")
    after = cur.fetchone()[0]
    cur.close()
    return max(0, after - before)


# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Populate threat feeds SQLite DB from public sources.")
    ap.add_argument("--db", default=str(DB_PATH), help="Path to SQLite DB (default: threat_feeds.db)")
    ap.add_argument("--skip-openphish", action="store_true", help="Skip OpenPhish feed import")
    ap.add_argument("--skip-phishtank", action="store_true", help="Skip PhishTank import")
    ap.add_argument("--skip-urlhaus", action="store_true", help="Skip URLhaus import")
    args = ap.parse_args()

    con = connect_db(Path(args.db))
    ensure_schema(con)

    totals = {}

    if not args.skip_openphish:
        try:
            totals["openphish_feed_inserted"] = load_openphish_feed(con)
        except Exception as e:
            totals["openphish_feed_error"] = str(e)

    # Skipping OpenPhish Archival by request.

    if not args.skip_phishtank:
        try:
            totals["phishtank_upserted"] = load_phishtank_archival(con)
        except Exception as e:
            totals["phishtank_error"] = str(e)

    if not args.skip_urlhaus:
        try:
            totals["urlhaus_inserted"] = load_urlhaus_recent(con)
        except Exception as e:
            totals["urlhaus_error"] = str(e)

    con.close()

    for k, v in totals.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()
