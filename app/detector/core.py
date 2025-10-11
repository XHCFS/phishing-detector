from __future__ import print_function
import os
import re
import json
import base64
import sqlite3
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

# Gmail API scope (read-only)
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Database to store emails and extracted URLs
DB_DIR = Path(__file__).resolve().parents[1] / 'database'
DB_DIR.mkdir(parents=True, exist_ok=True)
EMAILS_DB_PATH = DB_DIR / 'emails.db'


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


def setup_database(db_path: Path = EMAILS_DB_PATH):
    """Create `emails` and `email_urls` tables.

    `email_urls` mirrors many fields from enriched_threats and links to emails via email_id.
    """
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    # Emails table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        sender TEXT,
        subject TEXT,
        date TEXT,
        headers_json TEXT,
        body_plain TEXT,
        body_html TEXT,
        fetched_at DATETIME DEFAULT (datetime('now'))
    )
    ''')

    # email_urls table: mirrors many enriched_threats fields plus email_id
    cur.execute('''
    CREATE TABLE IF NOT EXISTS email_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id TEXT,
        url TEXT,
        domain TEXT,
        online TEXT,
        http_status_code INTEGER,
        ip_address TEXT,
        cidr_block TEXT,
        asn INTEGER,
        asn_name TEXT,
        isp TEXT,
        country TEXT,
        country_name TEXT,
        region TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL,
        ssl_enabled TEXT,
        cert_issuer TEXT,
        cert_subject TEXT,
        cert_valid_from TEXT,
        cert_valid_to TEXT,
        cert_serial TEXT,
        tld TEXT,
        registrar TEXT,
        creation_date TEXT,
        expiry_date TEXT,
        updated_date TEXT,
        name_servers TEXT,
        page_language TEXT,
        page_title TEXT,
        threat_type TEXT,
        target_brand TEXT,
        threat_tags TEXT,
        source_feed TEXT,
        source_id TEXT,
        first_seen DATETIME,
        last_seen DATETIME,
        last_checked DATETIME,
        notes TEXT,
        created_at DATETIME DEFAULT (datetime('now'))
    )
    ''')

    con.commit()
    con.close()


def save_email_to_db(msg_id: str, sender: str, subject: str, date: str, headers: dict, body_plain: str, body_html: str, db_path: Path = EMAILS_DB_PATH):
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    try:
        cur.execute('''
        INSERT INTO emails (id, sender, subject, date, headers_json, body_plain, body_html)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            msg_id,
            sender,
            subject,
            date,
            json.dumps(headers, ensure_ascii=False),
            body_plain,
            body_html
        ))
        con.commit()
    except sqlite3.IntegrityError:
        # already exists
        pass
    finally:
        con.close()


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


def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    found = URL_REGEX.findall(text)
    # normalize and dedupe
    seen = set()
    out = []
    for u in found:
        u = u.strip().rstrip(')')
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def fetch_and_store_recent_emails(max_results: int = 25, credentials_path: Optional[str] = None, db_path: Path = EMAILS_DB_PATH):
    service = get_gmail_service(credentials_path)
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])

    if not messages:
        print('No messages found.')
        return []

    stored = []
    for msg in messages:
        msg_id = msg['id']
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

        save_email_to_db(msg_id, sender, subject, date, headers, body_plain, body_html, db_path)
        stored.append(msg_id)

    print(f'Fetched and stored {len(stored)} messages')
    return stored


def insert_enriched_into_email_urls(email_id: str, enriched: object, db_path: Path = EMAILS_DB_PATH):
    """Insert an EnrichmentData-like object into email_urls table.

    `enriched` can be either the EnrichmentData class instance from enrich.py or a dict.
    """
    # Accept dict or object with attributes
    def getval(obj, name):
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    fields = (
        'email_id','url','domain','online','http_status_code','ip_address','cidr_block','asn','asn_name','isp',
        'country','country_name','region','city','latitude','longitude','ssl_enabled','cert_issuer','cert_subject',
        'cert_valid_from','cert_valid_to','cert_serial','tld','registrar','creation_date','expiry_date','updated_date',
        'name_servers','page_language','page_title','threat_type','target_brand','threat_tags','source_feed','source_id',
        'first_seen','last_seen','last_checked','notes'
    )

    placeholders = ','.join('?' for _ in fields)
    sql = f"INSERT INTO email_urls ({','.join(fields)}) VALUES ({placeholders})"

    values = [getval(enriched, f) for f in fields]

    cur.execute(sql, values)
    con.commit()
    con.close()


def enrich_urls_for_email(email_id: str, db_path: Path = EMAILS_DB_PATH, max_per_email: int = 50):
    """Extract URLs from the stored email and enrich each URL, store results in both threat_feeds.db and email_urls."""
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute('SELECT body_plain, body_html FROM emails WHERE id = ?', (email_id,))
    row = cur.fetchone()
    if not row:
        con.close()
        return 0
    body_plain, body_html = row
    text = (body_plain or '') + '\n' + (body_html or '')
    urls = extract_urls_from_text(text)
    urls = urls[:max_per_email]

    inserted = 0
    for u in urls:
        # Enrich using synchronous enrich_url (simple path)
        try:
            enriched = enrich_module.enrich_url(u, source_feed='email', source_id=email_id)
        except Exception as e:
            print(f'Enrichment failed for {u}: {e}')
            enriched = None

        # Insert into threat_feeds.db using existing helper if available
        try:
            if enriched is not None:
                # insert into central enriched DB
                try:
                    db_module.insert_enriched_data(db_module.DB_PATH, enriched)
                except Exception:
                    # fallback: ignore duplicate/constraint issues
                    pass

            # Insert into local email_urls table
            insert_enriched_into_email_urls(email_id, enriched, db_path)
            inserted += 1
        except Exception as e:
            print(f'Failed to insert enriched row for {u}: {e}')

    con.close()
    return inserted


def analyze_email(email_id: str) -> str:
    # Convenience: enrich URLs for email and return summary
    setup_database()
    count = enrich_urls_for_email(email_id)
    return f'Scanned {email_id}: enriched {count} URLs'


if __name__ == '__main__':
    # CLI with bootstrap convenience command
    import argparse
    import time

    def enrich_all_emails_in_db(db_path: Path = EMAILS_DB_PATH):
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute('SELECT id FROM emails')
        rows = [r[0] for r in cur.fetchall()]
        con.close()

        total = 0
        for eid in rows:
            try:
                n = enrich_urls_for_email(eid, db_path=db_path)
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
        # If fetch returned ids, enrich those; otherwise enrich all emails in DB
        if stored:
            for eid in stored:
                try:
                    n = enrich_urls_for_email(eid)
                    print(f'Enriched {n} URLs for {eid}')
                    enriched_count += n
                except Exception as e:
                    print(f'Error enriching {eid}: {e}')
        else:
            enriched_count = enrich_all_emails_in_db()

        duration = time.time() - start
        print(f'Bootstrap finished: enriched {enriched_count} URL(s) in {duration:.1f}s')

    if args.fetch is not None:
        setup_database()
        fetch_and_store_recent_emails(max_results=args.fetch, credentials_path=args.credentials)

    if args.enrich_email:
        setup_database()
        n = enrich_urls_for_email(args.enrich_email)
        print(f'Enriched {n} URLs for {args.enrich_email}')

    if args.seed_sample:
        # Seed a sample email and an enriched URL into the emails.db for testing/dev
        setup_database()
        msg_id = 'seed-msg-001'
        sender = 'dev+seed@example.com'
        subject = 'Seeded test email'
        date = 'Fri, 10 Oct 2025 12:00:00 +0000'
        headers = {'From': sender, 'Subject': subject, 'Date': date}
        body_plain = 'This is a seeded email. Visit https://example-seed.test/login'
        body_html = '<p>This is a seeded email. Visit <a href="https://example-seed.test/login">link</a></p>'

        save_email_to_db(msg_id, sender, subject, date, headers, body_plain, body_html)
        print('Seeded email saved:', msg_id)

        # Minimal enriched dict matching insert_enriched_into_email_urls fields
        enriched = {
            'email_id': msg_id,
            'url': 'https://example-seed.test/login',
            'domain': 'example-seed.test',
            'online': 'yes',
            'http_status_code': 200,
            'ip_address': '198.51.100.10',
            'asn': 64512,
            'asn_name': 'Seed ASN',
            'isp': 'Seed ISP',
            'country': 'US',
            'country_name': 'United States',
            'region': 'CA',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'ssl_enabled': 'yes',
            'cert_issuer': 'Seed CA',
            'cert_subject': 'CN=example-seed.test',
            'tld': 'test',
            'page_title': 'Seed Login',
            'threat_type': 'phishing',
            'target_brand': 'SeedBank',
            'threat_tags': 'seeded',
            'source_feed': 'email',
            'source_id': msg_id
        }

        insert_enriched_into_email_urls(msg_id, enriched)
        print('Seeded enriched URL inserted for', msg_id)
        print(f'Enriched {n} URLs for {args.enrich_email}')

    if args.enrich_all:
        setup_database()
        total = enrich_all_emails_in_db()
        print(f'Enriched {total} URLs total')

