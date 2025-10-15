#!/usr/bin/env python3
"""
Debug script to check email database and help diagnose issues.
"""

import sqlite3
import sys
from pathlib import Path
from datetime import datetime

# Database path
THREAT_FEEDS_DB_PATH = Path(__file__).parent / "app" / "database" / "threat_feeds.db"

def check_database():
    """Check if database exists and show email table status."""
    print("=" * 70)
    print("Email Database Diagnostic")
    print("=" * 70)
    print()
    
    print(f"Database path: {THREAT_FEEDS_DB_PATH}")
    print(f"Database exists: {THREAT_FEEDS_DB_PATH.exists()}")
    print()
    
    if not THREAT_FEEDS_DB_PATH.exists():
        print("❌ Database file doesn't exist!")
        print("   Run: python -m app.detector.core --setup-db")
        return
    
    try:
        con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
        cur = con.cursor()
        
        # Check if emails table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'")
        if not cur.fetchone():
            print("❌ 'emails' table doesn't exist!")
            print("   Run: python -m app.detector.core --setup-db")
            con.close()
            return
        
        print("✓ 'emails' table exists")
        print()
        
        # Get table schema
        cur.execute("PRAGMA table_info(emails)")
        columns = cur.fetchall()
        print("Table Schema:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        print()
        
        # Count total emails
        cur.execute("SELECT COUNT(*) FROM emails")
        total = cur.fetchone()[0]
        print(f"Total emails in database: {total}")
        
        if total == 0:
            print()
            print("⚠️  No emails in database yet!")
            print()
            print("To add emails, run:")
            print("  python run.py emails --count 10 --enrich")
            print("  OR")
            print("  python run.py bootstrap --count 10")
            print("  OR")
            print("  python -m app.detector.core --fetch 10")
        else:
            # Show recent emails
            print()
            print("Recent emails:")
            cur.execute("""
                SELECT id, sender, subject, risk_score, fetched_at
                FROM emails
                ORDER BY fetched_at DESC
                LIMIT 5
            """)
            for row in cur.fetchall():
                email_id, sender, subject, risk, fetched = row
                print(f"  • {email_id[:10]}... - From: {sender[:30]} - Risk: {risk}")
                print(f"    Subject: {subject[:50]}")
                print(f"    Fetched: {fetched}")
                print()
            
            # Risk score distribution
            print("Risk Score Distribution:")
            cur.execute("""
                SELECT 
                    CASE 
                        WHEN risk_score >= 85 THEN 'Critical (85-100)'
                        WHEN risk_score >= 70 THEN 'High (70-84)'
                        WHEN risk_score >= 50 THEN 'Medium (50-69)'
                        ELSE 'Low (0-49)'
                    END as level,
                    COUNT(*) as count
                FROM emails
                GROUP BY level
                ORDER BY 
                    CASE level
                        WHEN 'Critical (85-100)' THEN 1
                        WHEN 'High (70-84)' THEN 2
                        WHEN 'Medium (50-69)' THEN 3
                        ELSE 4
                    END
            """)
            for row in cur.fetchall():
                level, count = row
                print(f"  {level}: {count}")
            print()
            
            # Check email_urls
            cur.execute("SELECT COUNT(*) FROM email_urls")
            url_links = cur.fetchone()[0]
            print(f"Email-URL links: {url_links}")
            
            # Check URLs from threat feeds
            cur.execute("""
                SELECT COUNT(DISTINCT et.id)
                FROM email_urls eu
                JOIN enriched_threats et ON eu.url_id = et.id
                WHERE et.source_feed != 'email'
            """)
            threat_urls = cur.fetchone()[0]
            print(f"URLs from threat feeds: {threat_urls}")
        
        con.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")
        import traceback
        traceback.print_exc()

def test_save():
    """Test saving an email to the database."""
    print()
    print("=" * 70)
    print("Testing Email Save Function")
    print("=" * 70)
    print()
    
    from app.detector.core import save_email_to_db, setup_database
    
    # Ensure database exists
    setup_database()
    
    test_id = "test-debug-" + str(int(datetime.now().timestamp()))
    print(f"Attempting to save test email with ID: {test_id}")
    
    result = save_email_to_db(
        msg_id=test_id,
        sender="test@example.com",
        subject="Test email for debugging",
        date="Wed, 15 Oct 2025 12:00:00 +0000",
        headers={"From": "test@example.com", "Subject": "Test"},
        body_plain="Test body",
        body_html="<p>Test body</p>",
        risk_score=0
    )
    
    if result:
        print("✓ Email saved successfully!")
        
        # Verify it's in the database
        con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
        cur = con.cursor()
        cur.execute("SELECT * FROM emails WHERE id = ?", (test_id,))
        if cur.fetchone():
            print("✓ Verified: Email found in database")
        else:
            print("✗ Error: Email not found in database after save")
        con.close()
    else:
        print("⊘ Email already existed (or error occurred)")

if __name__ == '__main__':
    from datetime import datetime
    
    import argparse
    parser = argparse.ArgumentParser(description='Debug email database')
    parser.add_argument('--check', action='store_true', help='Check database status')
    parser.add_argument('--test-save', action='store_true', help='Test saving an email')
    
    args = parser.parse_args()
    
    if args.test_save:
        test_save()
    elif args.check or not any([args.test_save, args.check]):
        check_database()

