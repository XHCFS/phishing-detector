from __future__ import print_function
import os
import re
import json
import base64
import sqlite3
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional
from email.header import decode_header

# Google auth imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from pathlib import Path

# Allow insecure transport for local development (http://localhost)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Local imports
from ..database import enrich as enrich_module
from ..database import db as db_module
from . import scoring

# Gmail API scope (read-only)
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Database path - using threat_feeds.db for all data
DB_DIR = Path(__file__).resolve().parents[1] / 'database'
DB_DIR.mkdir(parents=True, exist_ok=True)
THREAT_FEEDS_DB_PATH = DB_DIR / 'threat_feeds.db'


def decode_mime(s: str) -> str:
    """Decode MIME encoded headers."""
    if not s:
        return ''
    decoded = decode_header(s)
    parts = []
    for part, enc in decoded:
        if isinstance(part, bytes):
            try:
                parts.append(part.decode(enc or 'utf-8', errors='replace'))
            except Exception:
                parts.append(part.decode('utf-8', errors='replace'))
        else:
            parts.append(part)
    return ''.join(parts)


def get_gmail_service(credentials_path: Optional[str] = None):
    """Authenticate and return a Gmail API service instance.

    credentials_path: path to OAuth client secrets (credentials.json). If None,
    defaults to detector/credentials.json.
    """
    creds = None
    if credentials_path is None:
        credentials_path = Path(__file__).resolve().parents[0] / 'credentials.json'
    
    # Verify credentials file exists
    if not Path(credentials_path).exists():
        raise FileNotFoundError(f'Credentials file not found: {credentials_path}')

    token_path = Path(__file__).resolve().parents[0] / 'token.json'

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
            
            # Set explicit redirect URI to match Google Cloud Console config
            flow.redirect_uri = 'http://localhost:8080'
            
            # Try the local server method first, with a shorter timeout
            import socket
            import threading
            
            port_available = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('127.0.0.1', 8080))
                sock.close()
                port_available = True
            except OSError:
                pass
            
            if port_available:
                result = {'creds': None, 'error': None, 'completed': False}
                
                def run_oauth():
                    try:
                        result['creds'] = flow.run_local_server(
                            port=8080,
                            bind_addr='127.0.0.1',
                            authorization_prompt_message='',
                            success_message='Authentication complete! Close this tab.',
                            open_browser=True
                        )
                        result['completed'] = True
                    except Exception as e:
                        result['error'] = e
                        result['completed'] = True
                
                thread = threading.Thread(target=run_oauth, daemon=False)
                thread.start()
                thread.join(timeout=120)  # 2 minute timeout
                
                if result['completed'] and result['creds']:
                    creds = result['creds']
                elif result['error'] and 'NoneType' not in str(result['error']):
                    raise result['error']
                else:
                    # Fallback to manual flow if local server fails
                    print('\nLocal server method failed, switching to manual code entry...')
                    print('You will need to copy the authorization code manually.\n')
                    creds = None
            
            # Manual flow fallback
            if creds is None:
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
                flow.redirect_uri = 'http://localhost:8080'
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                print('Please visit this URL to authorize the application:')
                print(auth_url)
                print()
                
                # Try to open browser
                import webbrowser
                try:
                    webbrowser.open(auth_url)
                except Exception:
                    pass
                
                print('After authorization, you will be redirected to a URL.')
                print('Copy the ENTIRE URL from your browser address bar and paste it here.')
                print('(It will start with http://localhost:8080/ and contain a code parameter)')
                print()
                
                code_url = input('Enter the full redirect URL: ').strip()
                
                # Extract code from URL or use as-is if it's just the code
                if 'code=' in code_url:
                    flow.fetch_token(authorization_response=code_url)
                    creds = flow.credentials
                else:
                    # Assume it's just the code
                    flow.fetch_token(code=code_url)
                    creds = flow.credentials
            
            if creds is None:
                raise RuntimeError('OAuth flow returned None - authentication failed')
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)


def setup_database():
    """Ensure the threat_feeds.db database is properly initialized with all tables.
    
    This uses the schema from db.py which includes emails, email_urls, and enriched_threats tables.
    """
    # Use the create_db function from db module to ensure all tables exist
    db_module.create_db(THREAT_FEEDS_DB_PATH)


def save_email_to_db(msg_id: str, sender: str, subject: str, date: str, headers: dict, body_plain: str, body_html: str, risk_score: int = 0):
    """Save email to the database with optional risk score.
    
    Args:
        msg_id: Email message ID
        sender: Email sender
        subject: Email subject
        date: Email date
        headers: Email headers as dict
        body_plain: Plain text body
        body_html: HTML body
        risk_score: Risk score (0-100), defaults to 0
    
    Returns:
        True if email was newly inserted, False if it already existed
    """
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    inserted = False
    try:
        cur.execute('''
        INSERT INTO emails (id, sender, subject, date, headers_json, body_plain, body_html, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            msg_id,
            sender,
            subject,
            date,
            json.dumps(headers, ensure_ascii=False),
            body_plain,
            body_html,
            risk_score
        ))
        con.commit()
        inserted = True
    except sqlite3.IntegrityError:
        # Email already exists
        inserted = False
    except Exception as e:
        print(f'    ✗ Error saving email: {e}')
        inserted = False
    finally:
        con.close()
    
    return inserted


def update_email_risk_score(email_id: str, risk_score: int = None):
    """Update the risk score for an email.
    
    If risk_score is None, calculates it as the MAX of all linked URLs' risk scores.
    """
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    if risk_score is None:
        # Calculate risk score as MAX of all linked URLs
        cur.execute('''
            SELECT MAX(et.risk_score)
            FROM email_urls eu
            JOIN enriched_threats et ON eu.url_id = et.id
            WHERE eu.email_id = ?
        ''', (email_id,))
        result = cur.fetchone()
        risk_score = result[0] if result and result[0] is not None else 0
    
    cur.execute('UPDATE emails SET risk_score = ? WHERE id = ?', (risk_score, email_id))
    con.commit()
    con.close()


def calculate_and_set_url_risk_score(url_id: int):
    """Calculate and update the risk score for a URL in enriched_threats.
    
    - If source_feed != 'email': risk_score = 100
    - If source_feed = 'email': calculate using scoring.py criteria
    """
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    # Get URL data
    cur.execute('''
        SELECT url, source_feed, http_status_code, online, last_seen, creation_date, tld
        FROM enriched_threats
        WHERE id = ?
    ''', (url_id,))
    row = cur.fetchone()
    
    if not row:
        con.close()
        return
    
    url, source_feed, http_status_code, online_status, last_seen, creation_date, tld = row
    
    # Determine risk score
    if source_feed != 'email':
        # External threat feed - always maximum risk
        risk_score = 100
    else:
        # Email source - calculate using scoring criteria
        risk_score = scoring.calculate_risk_score(
            url=url,
            http_status_code=http_status_code,
            online_status=online_status,
            last_seen=last_seen,
            creation_date=creation_date,
            tld=tld
        )
    
    # Update the risk score
    cur.execute('UPDATE enriched_threats SET risk_score = ? WHERE id = ?', (risk_score, url_id))
    con.commit()
    con.close()
    
    return risk_score


def extract_body(payload: dict) -> Tuple[str, str]:
    """Recursively extract plain text and HTML bodies from the payload."""
    body_plain, body_html = '', ''
    if not payload:
        return body_plain, body_html

    if 'parts' in payload:
        for part in payload.get('parts', []):
            p_text, p_html = extract_body(part)
            body_plain += p_text
            body_html += p_html
    else:
        mime = payload.get('mimeType', '')
        data = payload.get('body', {}).get('data')
        if data:
            decoded = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            if mime == 'text/plain':
                body_plain += decoded
            elif mime == 'text/html':
                body_html += decoded

    return body_plain, body_html


URL_REGEX = re.compile(r"https?://[\w\-\.\@:%_\+~#=\/\?&;,'()\[\]]+", re.IGNORECASE)


def normalize_url(url: str) -> str:
    """Normalize URL for consistent matching.
    
    - Strips whitespace and trailing punctuation
    - Removes URL fragments (#section)
    - Removes trailing slash (except for root URLs)
    - Lowercases scheme and domain
    - Removes default ports (80 for HTTP, 443 for HTTPS)
    """
    if not url:
        return url
    
    # Strip whitespace and common trailing punctuation
    url = url.strip().rstrip('.,;)')
    
    # Remove fragment (#section)
    if '#' in url:
        url = url.split('#')[0]
    
    # Parse URL into components
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        
        # Normalize scheme (lowercase)
        scheme = parsed.scheme.lower() if parsed.scheme else 'http'
        
        # Normalize domain (lowercase, remove default ports)
        netloc = parsed.netloc.lower() if parsed.netloc else ''
        
        # Remove default ports
        if ':80' in netloc and scheme == 'http':
            netloc = netloc.replace(':80', '')
        elif ':443' in netloc and scheme == 'https':
            netloc = netloc.replace(':443', '')
        
        # Normalize path (remove trailing slash except for root)
        path = parsed.path
        if path and path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        elif not path:
            path = '/'
        
        # Reconstruct URL
        normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ''))
        
        return normalized
    except Exception:
        # If parsing fails, return original with basic cleanup
        return url.strip()


def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    found = URL_REGEX.findall(text)
    # normalize and dedupe
    seen = set()
    out = []
    for u in found:
        u = normalize_url(u)
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def fetch_and_store_recent_emails(max_results: int = 25, credentials_path: Optional[str] = None):
    """Fetch recent emails from Gmail and store them in the database.
    
    Returns:
        List of message IDs that were stored
    """
    print(f'Fetching up to {max_results} recent emails from Gmail...')
    service = get_gmail_service(credentials_path)
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])

    if not messages:
        print('No messages found.')
        return []

    stored = []
    skipped = []
    
    for msg in messages:
        msg_id = msg['id']
        print(f'  Processing message {msg_id}...')
        
        try:
            msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            payload = msg_data.get('payload', {})
            headers_list = payload.get('headers', [])

            headers = {}
            for h in headers_list:
                headers[h['name']] = decode_mime(h.get('value', ''))

            sender = headers.get('From', '(unknown)')
            subject = headers.get('Subject', '(no subject)')
            date = headers.get('Date', '(unknown)')

            body_plain, body_html = extract_body(payload)

            print(f'    From: {sender}')
            print(f'    Subject: {subject[:50]}...')
            
            was_inserted = save_email_to_db(msg_id, sender, subject, date, headers, body_plain, body_html, risk_score=0)
            
            if was_inserted:
                stored.append(msg_id)
                print(f'    ✓ Saved to database (new email)')
            else:
                skipped.append(msg_id)
                print(f'    ⊘ Already in database (skipped)')
                
        except Exception as e:
            print(f'    ✗ Error processing message: {e}')

    print(f'\n✅ Fetched {len(messages)} messages: {len(stored)} new, {len(skipped)} already existed')
    return stored


def link_email_to_url(email_id: str, url_id: int):
    """Link an email to a URL in enriched_threats via the email_urls table.
    
    Args:
        email_id: Email message ID
        url_id: ID from enriched_threats table
    """
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    try:
        cur.execute(
            'INSERT OR IGNORE INTO email_urls (email_id, url_id) VALUES (?, ?)',
            (email_id, url_id)
        )
        con.commit()
    except sqlite3.IntegrityError:
        # Duplicate entry, ignore
        pass
    finally:
        con.close()


async def enrich_urls_for_email_async(email_id: str, max_per_email: int = 50, max_workers: int = 10):
    """Extract URLs from email and process them according to threat detection logic (ASYNC VERSION).
    
    This version enriches multiple URLs in parallel for much faster processing.
    
    Logic flow:
    1. Extract URLs from email
    2. For each URL:
       - Check if URL exists in enriched_threats with source_feed != 'email'
         - If yes: mark email as risk_score=100 (known threat)
       - If not found in non-email threats:
         - Check if URL exists in enriched_threats with source_feed='email'
           - If yes: link email to existing URL
           - If no: enrich URL, add to enriched_threats with source_feed='email', then link
    
    Returns:
        Number of URLs processed
    """
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    # Check if email has already been enriched (has URL links)
    cur.execute('SELECT COUNT(*) FROM email_urls WHERE email_id = ?', (email_id,))
    existing_links = cur.fetchone()[0]
    
    if existing_links > 0:
        print(f'\n⊘ Email {email_id} already enriched ({existing_links} URLs linked)')
        print(f'   Skipping to prevent duplicate enrichment')
        cur.close()
        return 0
    
    # Get email content
    cur.execute('SELECT body_plain, body_html FROM emails WHERE id = ?', (email_id,))
    row = cur.fetchone()
    if not row:
        print(f'\n✗ Email {email_id} not found in database')
        con.close()
        return 0
    
    body_plain, body_html = row
    text = (body_plain or '') + '\n' + (body_html or '')
    urls = extract_urls_from_text(text)
    urls = urls[:max_per_email]
    
    if not urls:
        con.close()
        return 0
    
    processed_count = 0
    url_risk_scores = []  # Track all risk scores for this email
    
    print(f'Processing {len(urls)} extracted URLs...')
    
    # Process each URL with clear, simple logic
    for url in urls:
        try:
            # Normalize URL for consistent matching
            normalized_url = normalize_url(url)
            print(f'\n  Processing: {normalized_url}')
            
            # STEP 1: Check if URL exists with source_feed != 'email'
            # If YES: Mark as 100, link it, DON'T overwrite
            cur.execute(
                'SELECT id, source_feed, risk_score FROM enriched_threats WHERE url = ? AND source_feed != ?',
                (normalized_url, 'email')
            )
            threat_match = cur.fetchone()
            
            if threat_match:
                url_id, source_feed, existing_risk = threat_match
                print(f'    ✓ FOUND in threat feed: {source_feed}')
                print(f'    → Setting risk_score = 100 (external threat)')
                
                # Set risk score to 100 for external threats
                calculate_and_set_url_risk_score(url_id)
                url_risk_scores.append(100)
                
                # Link to email (don't overwrite the URL entry!)
                link_email_to_url(email_id, url_id)
                processed_count += 1
                continue  # Done with this URL, move to next
            
            # STEP 2: Check if URL exists with source_feed = 'email'
            # If YES: Calculate risk score, link it
            cur.execute(
                'SELECT id FROM enriched_threats WHERE url = ? AND source_feed = ?',
                (normalized_url, 'email')
            )
            email_match = cur.fetchone()
            
            if email_match:
                url_id = email_match[0]
                print(f'    ✓ FOUND in database (email source)')
                
                # Calculate risk score using scoring.py criteria
                risk_score = calculate_and_set_url_risk_score(url_id)
                url_risk_scores.append(risk_score if risk_score else 0)
                print(f'    → Calculated risk_score = {risk_score}')
                
                # Link to email
                link_email_to_url(email_id, url_id)
                processed_count += 1
                continue  # Done with this URL, move to next
            
            # STEP 3: URL doesn't exist - need to add it
            # Enrich it and add with source_feed='email'
            print(f'    → New URL, enriching...')
            
        except Exception as e:
            print(f'    ✗ Error checking URL: {e}')
            continue
    
    con.close()
    
    # Now handle new URLs that need enrichment (Step 3 continuation)
    # Re-open connection and find URLs that weren't processed yet
    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
    cur = con.cursor()
    
    urls_to_enrich = []
    for url in urls:
        normalized_url = normalize_url(url)
        # Check if this URL was already processed
        cur.execute('SELECT id FROM enriched_threats WHERE url = ?', (normalized_url,))
        if not cur.fetchone():
            urls_to_enrich.append(normalized_url)
    
    con.close()
    
    # Enrich new URLs in parallel using async
    if urls_to_enrich:
        print(f'\n  Enriching {len(urls_to_enrich)} new URLs in parallel...')
        
        executor = ThreadPoolExecutor(max_workers=max_workers)
        
        try:
            # Create enrichment tasks
            tasks = [
                enrich_module.enrich_url_async(
                    url, 
                    source_feed='email', 
                    source_id=email_id,
                    executor=executor
                )
                for url in urls_to_enrich
            ]
            
            # Process all URLs concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Insert enriched data
            for i, result in enumerate(results):
                url = urls_to_enrich[i]
                
                if isinstance(result, Exception):
                    print(f'    ✗ Failed to enrich {url}: {result}')
                    continue
                
                try:
                    # Final check before insert (race condition protection)
                    con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
                    cur = con.cursor()
                    cur.execute('SELECT id, source_feed FROM enriched_threats WHERE url = ?', (url,))
                    race_check = cur.fetchone()
                    
                    if race_check:
                        # URL was added by another process - use existing
                        url_id, source_feed = race_check
                        print(f'    ⚠️  {url} was added during enrichment (source: {source_feed})')
                        con.close()
                        
                        if source_feed != 'email':
                            # It's a threat feed URL now!
                            risk_score = 100
                            calculate_and_set_url_risk_score(url_id)
                        else:
                            risk_score = calculate_and_set_url_risk_score(url_id)
                        
                        url_risk_scores.append(risk_score if risk_score else 0)
                        link_email_to_url(email_id, url_id)
                        processed_count += 1
                    else:
                        # Safe to insert
                        con.close()
                        enrich_module.insert_enriched_data(THREAT_FEEDS_DB_PATH, result)
                        
                        # Get the newly inserted ID
                        con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
                        cur = con.cursor()
                        cur.execute('SELECT id FROM enriched_threats WHERE url = ?', (url,))
                        new_row = cur.fetchone()
                        con.close()
                        
                        if new_row:
                            url_id = new_row[0]
                            risk_score = calculate_and_set_url_risk_score(url_id)
                            url_risk_scores.append(risk_score if risk_score else 0)
                            link_email_to_url(email_id, url_id)
                            processed_count += 1
                            print(f'    ✓ Enriched and linked: {url} (risk_score: {risk_score})')
                        
                except Exception as e:
                    print(f'    ✗ Failed to process {url}: {e}')
        
        finally:
            executor.shutdown(wait=True)
    
    # Calculate email risk score as MAX of all URL risk scores
    if url_risk_scores:
        max_risk_score = max(url_risk_scores)
    else:
        max_risk_score = 0
    
    # Update email risk score
    update_email_risk_score(email_id, risk_score=max_risk_score)
    
    # Report final risk level
    risk_level = scoring.get_risk_level(max_risk_score)
    print(f'\n📊 Email Risk Assessment:')
    print(f'   Processed {processed_count} URLs')
    print(f'   URL Risk Scores: {url_risk_scores}')
    print(f'   Maximum Risk Score: {max_risk_score}')
    
    if max_risk_score >= 85:
        print(f'   🚨 Email {email_id} marked as {risk_level.upper()} RISK')
    elif max_risk_score >= 70:
        print(f'   ⚠️  Email {email_id} marked as {risk_level.upper()} RISK')
    elif max_risk_score >= 50:
        print(f'   ⚡ Email {email_id} marked as {risk_level.upper()} RISK')
    else:
        print(f'   ✓ Email {email_id} marked as {risk_level.upper()} RISK')
    
    return processed_count


def enrich_urls_for_email(email_id: str, max_per_email: int = 50, force: bool = False):
    """Synchronous wrapper for async email URL enrichment.
    
    This runs the async version in an event loop for backwards compatibility.
    
    Args:
        email_id: Email message ID
        max_per_email: Maximum URLs to process per email
        force: If True, re-enrich even if already enriched
    """
    # If force flag, clear existing email-URL links first
    if force:
        con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
        cur = con.cursor()
        cur.execute('DELETE FROM email_urls WHERE email_id = ?', (email_id,))
        con.commit()
        con.close()
        print(f'🔄 Force re-enrichment: Cleared existing URL links for {email_id}')
    
    try:
        # Try to get existing event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, create a new one in a thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    enrich_urls_for_email_async(email_id, max_per_email)
                )
                return future.result()
        else:
            return loop.run_until_complete(enrich_urls_for_email_async(email_id, max_per_email))
    except RuntimeError:
        # No event loop, create new one
        return asyncio.run(enrich_urls_for_email_async(email_id, max_per_email))


def analyze_email(email_id: str) -> str:
    # Convenience: enrich URLs for email and return summary
    setup_database()
    count = enrich_urls_for_email(email_id)
    return f'Scanned {email_id}: enriched {count} URLs'


if __name__ == '__main__':
    # CLI with bootstrap convenience command
    import argparse
    import time

    def enrich_all_emails_in_db():
        con = sqlite3.connect(str(THREAT_FEEDS_DB_PATH))
        cur = con.cursor()
        
        # Get unenriched emails only (unless --force-enrich is used)
        if args.force_enrich:
            cur.execute('SELECT id FROM emails')
            print('🔄 Force re-enrichment mode: processing ALL emails')
        else:
            # Only get emails that haven't been enriched yet
            cur.execute('''
                SELECT e.id 
                FROM emails e
                LEFT JOIN email_urls eu ON e.id = eu.email_id
                WHERE eu.email_id IS NULL
            ''')
            print('Processing only unenriched emails (use --force-enrich to re-process all)')
        
        rows = [r[0] for r in cur.fetchall()]
        con.close()
        
        if not rows:
            print('No unenriched emails found')
            return 0

        print(f'Found {len(rows)} emails to enrich')
        total = 0
        for eid in rows:
            try:
                n = enrich_urls_for_email(eid, force=args.force_enrich)
                print(f'Enriched {n} URLs for {eid}')
                total += n
            except Exception as e:
                print(f'Error enriching {eid}: {e}')
        return total

    parser = argparse.ArgumentParser(description='Gmail fetcher and enricher')
    parser.add_argument('--setup-db', action='store_true', help='Create emails DB and tables')
    parser.add_argument('--fetch', type=int, nargs='?', const=25, help='Fetch recent emails (count)')
    parser.add_argument('--enrich-email', type=str, help='Enrich URLs for a specific email id')
    parser.add_argument('--enrich-all', action='store_true', help='Enrich URLs for all emails in the local DB')
    parser.add_argument('--force-enrich', action='store_true', help='Force re-enrichment even if email already enriched')
    parser.add_argument('--credentials', type=str, help='Path to credentials.json (OAuth client)')
    parser.add_argument('--bootstrap', action='store_true', help='One-shot: setup DB, fetch emails, then enrich them')
    parser.add_argument('--max-fetch', type=int, default=50, help='Max messages to fetch during bootstrap')
    parser.add_argument('--seed-sample', action='store_true', help='Insert a sample email and enriched URL into the emails DB')
    parser.add_argument('--authenticate', action='store_true', help='Complete Gmail OAuth authentication (run before starting the web app)')

    args = parser.parse_args()

    if args.setup_db:
        setup_database()
        print('Database created')

    if args.authenticate:
        print('Starting Gmail OAuth authentication...')
        print('A browser window will open. Please complete the authentication.')
        print('This uses port 8080 for the OAuth callback.')
        print('Waiting for authentication to complete (timeout: 5 minutes)...')
        print('')
        import sys
        try:
            service = get_gmail_service(credentials_path=args.credentials)
            # Verify the service works by making a test call
            service.users().getProfile(userId='me').execute()
            print('')
            print('✓ Authentication successful!')
            print('token.json has been created/updated.')
            print('You can now start the web app with ./run.sh')
            sys.exit(0)
        except KeyboardInterrupt:
            print('')
            print('✗ Authentication cancelled by user')
            sys.exit(1)
        except Exception as e:
            print('')
            print(f'✗ Authentication failed: {e}')
            print('')
            print('Troubleshooting tips:')
            print('1. Make sure credentials.json exists in app/detector/')
            print('2. Check that port 8080 is not in use')
            print('3. Try again and complete the OAuth flow in the browser')
            import traceback
            traceback.print_exc()
            sys.exit(1)

    if args.bootstrap:
        # One-shot flow: create DB, fetch messages, then enrich them
        setup_database()
        print('Starting bootstrap: creating DB, fetching messages, enriching...')
        start = time.time()

        try:
            stored = fetch_and_store_recent_emails(max_results=args.max_fetch, credentials_path=args.credentials)
        except Exception as e:
            print('Failed to fetch messages during bootstrap:', e)
            stored = []

        enriched_count = 0
        # Only enrich newly fetched emails (don't re-enrich all if nothing new)
        if stored:
            print(f'\nEnriching {len(stored)} newly fetched emails...')
            for eid in stored:
                try:
                    n = enrich_urls_for_email(eid)
                    print(f'Enriched {n} URLs for {eid}')
                    enriched_count += n
                except Exception as e:
                    print(f'Error enriching {eid}: {e}')
        else:
            print('\n⊘ No new emails to enrich (all were already in database)')
            print('   Tip: To re-enrich existing emails, use: --enrich-all')

        duration = time.time() - start
        print(f'\nBootstrap finished: enriched {enriched_count} URL(s) in {duration:.1f}s')

    if args.fetch is not None:
        setup_database()
        fetch_and_store_recent_emails(max_results=args.fetch, credentials_path=args.credentials)

    if args.enrich_email:
        setup_database()
        n = enrich_urls_for_email(args.enrich_email)
        print(f'Enriched {n} URLs for {args.enrich_email}')

    if args.seed_sample:
        # Seed a sample email and test the enrichment flow
        setup_database()
        msg_id = 'seed-msg-001'
        sender = 'dev+seed@example.com'
        subject = 'Seeded test email'
        date = 'Fri, 10 Oct 2025 12:00:00 +0000'
        headers = {'From': sender, 'Subject': subject, 'Date': date}
        body_plain = 'This is a seeded email. Visit https://example-seed.test/login'
        body_html = '<p>This is a seeded email. Visit <a href="https://example-seed.test/login">link</a></p>'

        save_email_to_db(msg_id, sender, subject, date, headers, body_plain, body_html, risk_score=0)
        print('Seeded email saved:', msg_id)

        # Now enrich the URLs in the email using the normal flow
        n = enrich_urls_for_email(msg_id)
        print(f'Seeded email processed: enriched {n} URLs')

    if args.enrich_all:
        setup_database()
        total = enrich_all_emails_in_db()
        print(f'Enriched {total} URLs total')

