#!/usr/bin/env python3
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "app" / "database" / "threat_feeds.db"

con = sqlite3.connect(str(DB_PATH))
cur = con.cursor()

print("=" * 70)
print("Checking for Duplicate Issues")
print("=" * 70)
print()

# Check for duplicate URLs in enriched_threats
print("1. Checking for duplicate URLs in enriched_threats table:")
cur.execute("""
    SELECT url, COUNT(*) as count 
    FROM enriched_threats 
    GROUP BY url 
    HAVING COUNT(*) > 1 
    ORDER BY count DESC 
    LIMIT 10
""")
duplicates = cur.fetchall()

if duplicates:
    print(f"   ❌ FOUND {len(duplicates)} duplicate URLs!")
    for url, count in duplicates:
        print(f"   • {url[:60]}... appears {count} times")
else:
    print("   ✓ No duplicate URLs found (good!)")

print()

# Check email_urls for the same email_id+url_id combinations
print("2. Checking email_urls table for duplicate (email_id, url_id) pairs:")
cur.execute("""
    SELECT email_id, url_id, COUNT(*) as count
    FROM email_urls
    GROUP BY email_id, url_id
    HAVING COUNT(*) > 1
    LIMIT 10
""")
dup_links = cur.fetchall()

if dup_links:
    print(f"   ❌ FOUND {len(dup_links)} duplicate email-URL links!")
    for email_id, url_id, count in dup_links:
        print(f"   • Email {email_id[:10]}... + URL {url_id} appears {count} times")
else:
    print("   ✓ No duplicate email-URL links (good!)")

print()

# Check for emails with excessive URL counts
print("3. Emails with the most URL links:")
cur.execute("""
    SELECT email_id, COUNT(*) as count
    FROM email_urls
    GROUP BY email_id
    ORDER BY count DESC
    LIMIT 5
""")
for email_id, count in cur.fetchall():
    cur.execute("SELECT sender, subject FROM emails WHERE id = ?", (email_id,))
    email_data = cur.fetchone()
    if email_data:
        sender, subject = email_data
        print(f"   • {email_id[:10]}... has {count} URLs")
        print(f"     From: {sender[:40]}")
        print(f"     Subject: {subject[:50]}")

print()

# Check if enrichment has been run multiple times on same emails
print("4. Checking if same email was enriched multiple times:")
cur.execute("""
    SELECT 
        eu.email_id,
        COUNT(DISTINCT eu.url_id) as unique_urls,
        COUNT(*) as total_links
    FROM email_urls eu
    GROUP BY eu.email_id
    HAVING COUNT(*) > COUNT(DISTINCT eu.url_id)
    LIMIT 5
""")
multi_enrich = cur.fetchall()

if multi_enrich:
    print(f"   ❌ FOUND emails with duplicate URL links!")
    for email_id, unique, total in multi_enrich:
        print(f"   • Email {email_id[:10]}... has {unique} unique URLs but {total} total links")
else:
    print("   ✓ No duplicate enrichment detected")

print()

# Summary
print("=" * 70)
print("Summary:")
cur.execute("SELECT COUNT(*) FROM emails")
email_count = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM email_urls")
link_count = cur.fetchone()[0]
cur.execute("SELECT COUNT(DISTINCT url_id) FROM email_urls")
unique_url_count = cur.fetchone()[0]

print(f"  Total emails: {email_count}")
print(f"  Total email-URL links: {link_count}")
print(f"  Unique URLs linked: {unique_url_count}")
print(f"  Average URLs per email: {link_count / max(email_count, 1):.1f}")

con.close()

