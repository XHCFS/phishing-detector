#!/usr/bin/env python3
"""
Diagnostic script to check URL matching between emails and threat feeds.
Helps troubleshoot why URLs might not be matching.
"""

import sqlite3
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from app.detector.core import normalize_url, THREAT_FEEDS_DB_PATH

def check_url_in_database(url: str):
    """Check if a URL exists in the database and show matching details."""
    normalized = normalize_url(url)
    
    print(f"Original URL: {url}")
    print(f"Normalized:   {normalized}")
    print()
    
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    # Check for exact match
    cur.execute('''
        SELECT id, url, source_feed, risk_score, threat_type, target_brand
        FROM enriched_threats
        WHERE url = ?
    ''', (normalized,))
    
    exact_match = cur.fetchone()
    
    if exact_match:
        url_id, db_url, source_feed, risk_score, threat_type, target_brand = exact_match
        print(f"✓ EXACT MATCH FOUND!")
        print(f"  ID: {url_id}")
        print(f"  URL: {db_url}")
        print(f"  Source Feed: {source_feed}")
        print(f"  Risk Score: {risk_score}")
        print(f"  Threat Type: {threat_type}")
        print(f"  Target Brand: {target_brand}")
        
        if source_feed == 'email':
            print(f"  ⚠️  WARNING: Source is 'email', won't trigger high risk!")
        else:
            print(f"  ✓ Source is NOT 'email', WILL trigger risk score 100!")
    else:
        print(f"✗ NO EXACT MATCH")
        
        # Try to find similar URLs
        from urllib.parse import urlparse
        parsed = urlparse(normalized)
        domain = parsed.netloc
        
        print(f"\n Searching for similar URLs with domain: {domain}")
        cur.execute('''
            SELECT id, url, source_feed, risk_score
            FROM enriched_threats
            WHERE domain = ?
            LIMIT 5
        ''', (domain,))
        
        similar = cur.fetchall()
        if similar:
            print(f"  Found {len(similar)} URLs with same domain:")
            for url_id, db_url, source_feed, risk_score in similar:
                print(f"    • {db_url}")
                print(f"      Source: {source_feed}, Risk: {risk_score}")
        else:
            print(f"  No URLs found with domain: {domain}")
    
    con.close()
    print()

def show_threat_feed_stats():
    """Show statistics about threat feeds."""
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    print("=" * 70)
    print("Threat Feed Statistics")
    print("=" * 70)
    
    # Count by source
    cur.execute('''
        SELECT source_feed, COUNT(*) as count
        FROM enriched_threats
        WHERE source_feed != 'email'
        GROUP BY source_feed
        ORDER BY count DESC
    ''')
    
    print("\nExternal Threat Feeds:")
    for source, count in cur.fetchall():
        print(f"  {source}: {count:,} URLs")
    
    # Count email sources
    cur.execute('''
        SELECT COUNT(*) FROM enriched_threats WHERE source_feed = 'email'
    ''')
    email_count = cur.fetchone()[0]
    print(f"\nEmail Sources: {email_count:,} URLs")
    
    # Total
    cur.execute('SELECT COUNT(*) FROM enriched_threats')
    total = cur.fetchone()[0]
    print(f"\nTotal URLs in database: {total:,}")
    
    con.close()
    print()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Check URL matching in threat database')
    parser.add_argument('url', nargs='?', help='URL to check')
    parser.add_argument('--stats', action='store_true', help='Show threat feed statistics')
    
    args = parser.parse_args()
    
    if args.stats:
        show_threat_feed_stats()
    
    if args.url:
        check_url_in_database(args.url)
    
    if not args.stats and not args.url:
        parser.print_help()
        print()
        print("Examples:")
        print("  python check_url_matching.py 'https://example.com/phishing'")
        print("  python check_url_matching.py --stats")

if __name__ == '__main__':
    main()


