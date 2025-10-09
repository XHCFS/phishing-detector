#!/usr/bin/env python3
"""
Enrichment pipeline for threat feeds data.

Reads URLs from threat_feeds_raw.db and enriches them with:
- WHOIS information (domain registration, registrar, dates, nameservers)
- GeoIP data (country, region, city, coordinates)
- ASN/ISP information (network owner, ISP name)
- SSL certificate details (issuer, validity, serial)
- DNS resolution (IP addresses)

Stores enriched data in threat_feeds.db (enriched_threats table).
"""

import ssl
import socket
import sqlite3
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone
import logging

# Optional dependencies - graceful degradation if not available
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not installed. WHOIS lookups disabled.")
    print("Install with: pip install python-whois")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests not installed. HTTP checks disabled.")
    print("Install with: pip install requests")

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("Warning: geoip2 not installed. GeoIP lookups disabled.")
    print("Install with: pip install geoip2")

try:
    from langdetect import detect, LangDetectException
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False
    print("Warning: langdetect not installed. Language detection will use heuristics.")
    print("Install with: pip install langdetect")

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print("Warning: ipwhois not installed. ASN lookups disabled.")
    print("Install with: pip install ipwhois")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database paths
DB_DIR = Path(__file__).parent
RAW_DB_PATH = DB_DIR / "threat_feeds_raw.db"
ENRICHED_DB_PATH = DB_DIR / "threat_feeds.db"

# GeoIP database paths (MaxMind GeoLite2)
GEOIP_CITY_DB = DB_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_DB = DB_DIR / "GeoLite2-ASN.mmdb"

# Rate limiting and timeouts
WHOIS_DELAY = 1.0  # seconds between WHOIS queries
DNS_TIMEOUT = 5.0  # seconds
SSL_TIMEOUT = 5.0  # Seconds
HTTP_TIMEOUT = 10.0  # seconds
MAX_RETRIES = 2


class EnrichmentData:
    """Container for enriched data fields."""

    def __init__(self):
        # Basic
        self.url: Optional[str] = None
        self.domain: Optional[str] = None

        # Status
        self.online: Optional[str] = None
        self.http_status_code: Optional[int] = None

        # Network
        self.ip_address: Optional[str] = None
        self.cidr_block: Optional[str] = None
        self.asn: Optional[int] = None
        self.asn_name: Optional[str] = None
        self.isp: Optional[str] = None

        # Geographic
        self.country: Optional[str] = None
        self.country_name: Optional[str] = None
        self.region: Optional[str] = None
        self.city: Optional[str] = None
        self.latitude: Optional[float] = None
        self.longitude: Optional[float] = None

        # SSL/TLS
        self.ssl_enabled: Optional[str] = None
        self.cert_issuer: Optional[str] = None
        self.cert_subject: Optional[str] = None
        self.cert_valid_from: Optional[str] = None
        self.cert_valid_to: Optional[str] = None
        self.cert_serial: Optional[str] = None

        # WHOIS
        self.tld: Optional[str] = None
        self.registrar: Optional[str] = None
        self.creation_date: Optional[str] = None
        self.expiry_date: Optional[str] = None
        self.updated_date: Optional[str] = None
        self.name_servers: Optional[str] = None

        # Content
        self.page_language: Optional[str] = None
        self.page_title: Optional[str] = None

        # Threat info
        self.threat_type: Optional[str] = None
        self.target_brand: Optional[str] = None
        self.threat_tags: Optional[str] = None

        # Source
        self.source_feed: Optional[str] = None
        self.source_id: Optional[str] = None

        # Timestamps
        self.first_seen: Optional[str] = None
        self.last_seen: Optional[str] = None

        # Notes
        self.notes: Optional[str] = None


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url if url.startswith(
            'http') else f'http://{url}')
        return parsed.hostname
    except Exception as e:
        logger.debug(f"Failed to extract domain from {url}: {e}")
        return None


def extract_tld(domain: str) -> Optional[str]:
    """Extract TLD from domain."""
    if not domain:
        return None
    parts = domain.split('.')
    return f".{parts[-1]}" if len(parts) > 1 else None


def resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address."""
    if not domain:
        return None
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout) as e:
        logger.debug(f"Failed to resolve {domain}: {e}")
        return None


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for domain."""
    if not WHOIS_AVAILABLE or not domain:
        return {}

    try:
        time.sleep(WHOIS_DELAY)  # Rate limiting
        w = whois.whois(domain)

        # Helper to extract first date from list or single value
        def extract_date(date_val):
            if date_val is None:
                return None
            if isinstance(date_val, list):
                date_val = date_val[0] if date_val else None
            if isinstance(date_val, datetime):
                return date_val.isoformat()
            return str(date_val) if date_val else None

        # Helper to extract first string from list
        def extract_string(val):
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            return str(val) if val else None

        return {
            'registrar': extract_string(w.registrar),
            'creation_date': extract_date(w.creation_date),
            'expiry_date': extract_date(w.expiration_date),
            'updated_date': extract_date(w.updated_date),
            'name_servers': ','.join(
                w.name_servers) if w.name_servers else None,
        }
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return {}


def get_geoip_info(ip_address: str) -> Dict[str, Any]:
    """Get GeoIP information for IP address."""
    if not ip_address:
        return {}

    result = {}

    # Try GeoIP databases if available
    if GEOIP_AVAILABLE:
        # Try City database
        if GEOIP_CITY_DB.exists():
            try:
                with geoip2.database.Reader(str(GEOIP_CITY_DB)) as reader:
                    response = reader.city(ip_address)
                    result.update({
                        'country': response.country.iso_code,
                        'country_name': response.country.name,
                        'region': response.subdivisions.most_specific.name
                        if response.subdivisions else None,
                        'city': response.city.name,
                        'latitude': response.location.latitude,
                        'longitude': response.location.longitude,
                    })
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP {ip_address} not found in GeoIP City DB")
            except Exception as e:
                logger.debug(f"GeoIP City lookup failed for {ip_address}: {e}")

        # Try ASN database
        if GEOIP_ASN_DB.exists():
            try:
                with geoip2.database.Reader(str(GEOIP_ASN_DB)) as reader:
                    response = reader.asn(ip_address)
                    result.update({
                        'asn': response.autonomous_system_number,
                        'asn_name': response.autonomous_system_organization,
                    })
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP {ip_address} not found in GeoIP ASN DB")
            except Exception as e:
                logger.debug(f"GeoIP ASN lookup failed for {ip_address}: {e}")

    # Fallback to free IP-API service if we don't have GeoIP data
    if not result and REQUESTS_AVAILABLE:
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result.update({
                        'country': data.get('countryCode'),
                        'country_name': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'asn': int(data.get('as', '').split()[0].replace(
                            'AS', '')) if data.get('as') else None,
                        'asn_name': ' '.join(data.get('as', '').split()[
                            1:]) if data.get('as') else None,
                        'isp': data.get('isp'),
                    })
                    time.sleep(0.5)  # Rate limit for free API
        except Exception as e:
            logger.debug(f"IP-API lookup failed for {ip_address}: {e}")

    return result


def get_asn_info_ipwhois(ip_address: str) -> Dict[str, Any]:
    """Get ASN/ISP information using IPWhois (fallback method)."""
    if not IPWHOIS_AVAILABLE or not ip_address:
        return {}

    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap(depth=1)

        return {
            'asn': int(result.get('asn', '').replace(
                'AS', '')) if result.get('asn') else None,
            'asn_name': result.get('asn_description'),
            'cidr_block': result.get('network', {}).get('cidr'),
            'isp': result.get('network', {}).get('name'),
            'country': result.get('asn_country_code'),
        }
    except Exception as e:
        logger.debug(f"IPWhois lookup failed for {ip_address}: {e}")
        return {}


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information."""
    if not domain:
        return {}

    try:
        context = ssl.create_default_context()
        with socket.create_connection(
                (domain, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_str = issuer.get(
                    'organizationName',
                    issuer.get('commonName', '')
                )

                # Extract subject
                subject = dict(x[0] for x in cert.get('subject', []))
                subject_str = subject.get('commonName', '')

                return {
                    'ssl_enabled': 'yes',
                    'cert_issuer': issuer_str,
                    'cert_subject': subject_str,
                    'cert_valid_from': cert.get('notBefore'),
                    'cert_valid_to': cert.get('notAfter'),
                    'cert_serial': cert.get('serialNumber'),
                }
    except socket.timeout:
        logger.debug(f"SSL connection timeout for {domain}")
        return {'ssl_enabled': 'no'}
    except ssl.SSLError as e:
        logger.debug(f"SSL error for {domain}: {e}")
        return {'ssl_enabled': 'no'}
    except Exception as e:
        logger.debug(f"SSL check failed for {domain}: {e}")
        return {'ssl_enabled': 'no'}


def get_page_content(url: str) -> Dict[str, Any]:
    """Get page content including title and language."""
    if not REQUESTS_AVAILABLE or not url:
        return {}

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        response = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False,  # Skip SSL verification for phishing sites
            headers={'User-Agent': 'Mozilla/5.0'}
        )

        result = {
            'online': 'yes' if response.status_code < 400 else 'no',
            'http_status_code': response.status_code
        }

        # Try to parse HTML for title and language
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')

            # Get page title
            if soup.title:
                result['page_title'] = soup.title.string.strip() if soup.title.string else None

            # Get language from html tag or meta tag
            html_tag = soup.find('html')
            if html_tag and html_tag.get('lang'):
                result['page_language'] = html_tag.get('lang')
            else:
                meta_lang = soup.find('meta', {'http-equiv': 'content-language'})
                if meta_lang:
                    result['page_language'] = meta_lang.get('content')

        except ImportError:
            # BeautifulSoup not available, just use regex
            import re
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                result['page_title'] = title_match.group(1).strip()[:200]

            lang_match = re.search(r'<html[^>]+lang=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            if lang_match:
                result['page_language'] = lang_match.group(1)

        return result

    except requests.exceptions.SSLError:
        # Try without SSL
        try:
            url = url.replace('https://', 'http://')
            response = requests.get(
                url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return {
                'online': 'yes' if response.status_code < 400 else 'no',
                'http_status_code': response.status_code
            }
        except Exception:
            return {'online': 'no', 'http_status_code': None}
    except requests.exceptions.Timeout:
        return {'online': 'unknown', 'http_status_code': None}
    except requests.exceptions.ConnectionError:
        return {'online': 'no', 'http_status_code': None}
    except Exception as e:
        logger.debug(f"Page content fetch failed for {url}: {e}")
        return {'online': 'unknown', 'http_status_code': None}


def check_online_status(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Check if URL is online and get HTTP status (lightweight HEAD request)."""
    if not REQUESTS_AVAILABLE or not url:
        return None, None

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        response = requests.head(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False  # Skip SSL verification for phishing sites
        )
        return 'yes', response.status_code
    except requests.exceptions.SSLError:
        # Try without SSL
        try:
            url = url.replace('https://', 'http://')
            response = requests.head(
                url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            return 'yes', response.status_code
        except Exception:
            return 'no', None
    except requests.exceptions.Timeout:
        return 'unknown', None
    except requests.exceptions.ConnectionError:
        return 'no', None
    except Exception as e:
        logger.debug(f"Online check failed for {url}: {e}")
        return 'unknown', None


def enrich_url(
        url: str,
        source_feed: str,
        source_id: Optional[str] = None,
        existing_data: Optional[Dict[str, Any]] = None
) -> EnrichmentData:
    """
    Enrich a single URL with all available data sources.

    Args:
        url: The URL to enrich
        source_feed: Source feed name
        source_id: Original ID from source feed
        existing_data: Any existing data from raw database

    Returns:
        EnrichmentData object with all enriched fields
    """
    data = EnrichmentData()
    data.url = url
    data.source_feed = source_feed
    data.source_id = source_id

    # Extract domain
    data.domain = extract_domain(url)
    if not data.domain:
        logger.warning(f"Could not extract domain from URL: {url}")
        return data

    data.tld = extract_tld(data.domain)

    # Copy existing data from raw database if available
    if existing_data:
        data.target_brand = existing_data.get('target')
        data.threat_tags = existing_data.get('tags')
        data.threat_type = existing_data.get('threat')
        data.online = existing_data.get('online')
        data.ip_address = existing_data.get('ip_address')
        data.cidr_block = existing_data.get('cidr_block')
        data.asn = existing_data.get('asn')
        data.country = existing_data.get('country')

    # Resolve IP if not already available
    if not data.ip_address:
        logger.info(f"Resolving IP for {data.domain}")
        data.ip_address = resolve_ip(data.domain)

    # Get WHOIS information
    logger.info(f"Fetching WHOIS for {data.domain}")
    whois_info = get_whois_info(data.domain)
    if whois_info:
        data.registrar = whois_info.get('registrar')
        data.creation_date = whois_info.get('creation_date')
        data.expiry_date = whois_info.get('expiry_date')
        data.updated_date = whois_info.get('updated_date')
        data.name_servers = whois_info.get('name_servers')

    # Get GeoIP information
    if data.ip_address:
        logger.info(f"Fetching GeoIP for {data.ip_address}")
        geoip_info = get_geoip_info(data.ip_address)
        if geoip_info:
            data.country = data.country or geoip_info.get('country')
            data.country_name = geoip_info.get('country_name')
            data.region = geoip_info.get('region')
            data.city = geoip_info.get('city')
            data.latitude = geoip_info.get('latitude')
            data.longitude = geoip_info.get('longitude')
            data.asn = data.asn or geoip_info.get('asn')
            data.asn_name = geoip_info.get('asn_name')

        # Use IPWhois to fill missing ASN or CIDR info
        # Note: Some CDNs (Cloudflare, etc.) don't expose CIDR via RDAP
        if IPWHOIS_AVAILABLE and (not data.asn or not data.cidr_block):
            logger.info(f"Fetching ASN/CIDR via IPWhois "
                       f"for {data.ip_address}")
            asn_info = get_asn_info_ipwhois(data.ip_address)
            if asn_info:
                data.asn = data.asn or asn_info.get('asn')
                data.asn_name = data.asn_name or asn_info.get('asn_name')
                data.cidr_block = (data.cidr_block or
                                  asn_info.get('cidr_block'))
                data.isp = data.isp or asn_info.get('isp')
                data.country = data.country or asn_info.get('country')
                
                # Log if CIDR is still missing (common for CDNs)
                if not data.cidr_block:
                    logger.debug(f"CIDR block not available for "
                               f"{data.ip_address} (ASN: {data.asn}) - "
                               f"CDN/cloud provider may not expose this data")

    # Get SSL certificate information
    logger.info(f"Checking SSL for {data.domain}")
    ssl_info = get_ssl_info(data.domain)
    if ssl_info:
        data.ssl_enabled = ssl_info.get('ssl_enabled')
        data.cert_issuer = ssl_info.get('cert_issuer')
        data.cert_subject = ssl_info.get('cert_subject')
        data.cert_valid_from = ssl_info.get('cert_valid_from')
        data.cert_valid_to = ssl_info.get('cert_valid_to')
        data.cert_serial = ssl_info.get('cert_serial')

    # Get page content (title, language, online status)
    if not data.online or not data.page_title:
        logger.info(f"Fetching page content for {url}")
        page_info = get_page_content(url)
        if page_info:
            data.online = data.online or page_info.get('online')
            data.http_status_code = page_info.get('http_status_code')
            data.page_title = page_info.get('page_title')
            data.page_language = page_info.get('page_language')

    # Fallback lightweight online check if still no status
    if not data.online:
        logger.info(f"Checking online status for {url}")
        online_status, http_code = check_online_status(url)
        data.online = online_status
        data.http_status_code = data.http_status_code or http_code

    # Fill ISP from ASN name if not already set
    if not data.isp and data.asn_name:
        data.isp = data.asn_name

    # Infer threat_type from source feed if not set
    if not data.threat_type:
        if source_feed == 'phishtank' or source_feed == 'openphish':
            data.threat_type = 'phishing'
        elif source_feed == 'urlhaus':
            data.threat_type = data.threat_type or 'malware'

    # Try to detect language from page title if language is missing
    if not data.page_language and data.page_title:
        if LANGDETECT_AVAILABLE:
            try:
                # Use langdetect for accurate language detection
                detected_lang = detect(data.page_title)
                data.page_language = detected_lang
                logger.info(f"Detected language '{detected_lang}' "
                          f"from title: {data.page_title[:50]}...")
            except LangDetectException:
                logger.debug(f"Could not detect language "
                           f"from title: {data.page_title}")
        else:
            # Fallback: Simple heuristic-based language detection
            title_lower = data.page_title.lower()
            if any(word in title_lower for word in
                   ['sign', 'login', 'account', 'verify',
                    'update', 'security']):
                data.page_language = 'en'
            elif any(word in title_lower for word in
                     ['iniciar', 'cuenta', 'verificar', 'actualizar']):
                data.page_language = 'es'
            elif any(word in title_lower for word in
                     ['connexion', 'compte', 'vérifier', 'mettre']):
                data.page_language = 'fr'
            elif any(word in title_lower for word in
                     ['anmelden', 'konto', 'überprüfen',
                      'aktualisieren']):
                data.page_language = 'de'
            elif any(word in title_lower for word in
                     ['accesso', 'conto', 'verificare', 'aggiornare']):
                data.page_language = 'it'

    # Fill country_name from country code if missing
    if data.country and not data.country_name:
        country_names = {
            'US': 'United States', 'CN': 'China', 'RU': 'Russia',
            'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France',
            'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India',
            'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia',
            'NL': 'Netherlands', 'IT': 'Italy', 'ES': 'Spain',
            'SE': 'Sweden', 'PL': 'Poland', 'TR': 'Turkey',
            'MX': 'Mexico', 'ID': 'Indonesia', 'TH': 'Thailand',
            'VN': 'Vietnam', 'PH': 'Philippines', 'MY': 'Malaysia',
            'SG': 'Singapore', 'HK': 'Hong Kong', 'TW': 'Taiwan',
        }
        data.country_name = country_names.get(data.country, data.country)

    # Set timestamps
    data.last_seen = datetime.now(timezone.utc).isoformat()

    return data


def get_raw_data(
        raw_db_path: Path
) -> List[Tuple[str, str, Optional[str], Dict[str, Any]]]:
    """
    Fetch URLs from raw database that need enrichment.

    Returns:
        List of (url, source_feed, source_id, existing_data) tuples
    """
    con = sqlite3.connect(str(raw_db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    results = []

    # Get OpenPhish feed data
    cur.execute("SELECT url, domain FROM openphish_feed")
    for row in cur.fetchall():
        results.append((
            row['url'],
            'openphish',
            None,
            {'domain': row['domain']}
        ))

    # Get PhishTank data
    cur.execute("""
        SELECT phish_id, url, online, target, ip_address,
               cidr_block, announcing_network, rir
        FROM phishtank_archival
    """)
    for row in cur.fetchall():
        # Parse ASN from announcing_network if it's a number
        asn = None
        if row['announcing_network']:
            try:
                asn = int(str(row['announcing_network']).replace('AS', '').strip())
            except (ValueError, AttributeError):
                asn = None

        results.append((
            row['url'],
            'phishtank',
            str(row['phish_id']),
            {
                'online': row['online'],
                'target': row['target'],
                'ip_address': row['ip_address'],
                'cidr_block': row['cidr_block'],
                'asn': asn,
                'rir': row['rir'],
            }
        ))

    # Get URLhaus data
    cur.execute("""
        SELECT url, threat, tags, asn, country
        FROM urlhaus_api
    """)
    for row in cur.fetchall():
        results.append((
            row['url'],
            'urlhaus',
            None,
            {
                'threat': row['threat'],
                'tags': row['tags'],
                'asn': row['asn'],
                'country': row['country'],
            }
        ))

    cur.close()
    con.close()

    logger.info(f"Found {len(results)} URLs to enrich from raw database")
    return results


def insert_enriched_data(enriched_db_path: Path, data: EnrichmentData):
    """Insert enriched data into the database."""
    con = sqlite3.connect(str(enriched_db_path))
    cur = con.cursor()

    cur.execute("""
        INSERT OR REPLACE INTO enriched_threats (
            url, domain, online, http_status_code,
            ip_address, cidr_block, asn, asn_name, isp,
            country, country_name, region, city, latitude, longitude,
            ssl_enabled, cert_issuer, cert_subject,
            cert_valid_from, cert_valid_to, cert_serial,
            tld, registrar, creation_date, expiry_date,
            updated_date, name_servers,
            page_language, page_title,
            threat_type, target_brand, threat_tags,
            source_feed, source_id, last_seen, last_checked,
            notes, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, datetime('now'), ?, datetime('now')
        )
    """, (
        data.url, data.domain, data.online, data.http_status_code,
        data.ip_address, data.cidr_block, data.asn, data.asn_name, data.isp,
        data.country, data.country_name, data.region, data.city,
        data.latitude, data.longitude,
        data.ssl_enabled, data.cert_issuer, data.cert_subject,
        data.cert_valid_from, data.cert_valid_to, data.cert_serial,
        data.tld, data.registrar, data.creation_date, data.expiry_date,
        data.updated_date, data.name_servers,
        data.page_language, data.page_title,
        data.threat_type, data.target_brand, data.threat_tags,
        data.source_feed, data.source_id, data.last_seen,
        data.notes
    ))

    con.commit()
    cur.close()
    con.close()


def check_already_enriched(enriched_db_path: Path, url: str) -> bool:
    """Check if URL is already enriched."""
    con = sqlite3.connect(str(enriched_db_path))
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM enriched_threats WHERE url = ?", (url,))
    count = cur.fetchone()[0]
    cur.close()
    con.close()
    return count > 0


def main():
    """Main enrichment pipeline."""
    parser = argparse.ArgumentParser(
        description="Enrich threat feed data with WHOIS, GeoIP, etc."
    )
    parser.add_argument(
        '--raw-db',
        default=str(RAW_DB_PATH),
        help='Path to raw database'
    )
    parser.add_argument(
        '--enriched-db',
        default=str(ENRICHED_DB_PATH),
        help='Path to enriched database'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of URLs to process'
    )
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='Skip URLs already in enriched database'
    )
    parser.add_argument(
        '--source',
        choices=['openphish', 'phishtank', 'urlhaus'],
        help='Process only specific source feed'
    )
    args = parser.parse_args()

    raw_db = Path(args.raw_db)
    enriched_db = Path(args.enriched_db)

    if not raw_db.exists():
        logger.error(f"Raw database not found: {raw_db}")
        return 1

    if not enriched_db.exists():
        logger.error(f"Enriched database not found: {enriched_db}")
        logger.info("Run 'python -m app.database.db' to create it")
        return 1

    # Warn about missing optional dependencies
    if not WHOIS_AVAILABLE:
        logger.warning("WHOIS lookups disabled - install python-whois")
    if not GEOIP_AVAILABLE:
        logger.warning("GeoIP lookups disabled - install geoip2")
        logger.info(
            "Download GeoLite2 databases from "
            "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
        )
    if not IPWHOIS_AVAILABLE:
        logger.warning("IPWhois lookups disabled - install ipwhois")
    if not REQUESTS_AVAILABLE:
        logger.warning("HTTP checks disabled - install requests")

    # Get raw data
    logger.info("Fetching URLs from raw database...")
    raw_urls = get_raw_data(raw_db)

    # Filter by source if specified
    if args.source:
        raw_urls = [
            r for r in raw_urls if r[1] == args.source
        ]
        logger.info(f"Filtered to {len(raw_urls)} URLs from {args.source}")

    # Apply limit
    if args.limit:
        raw_urls = raw_urls[:args.limit]
        logger.info(f"Limited to {args.limit} URLs")

    # Process each URL
    processed = 0
    skipped = 0
    failed = 0

    for url, source_feed, source_id, existing_data in raw_urls:
        try:
            # Skip if already enriched
            if args.skip_existing and check_already_enriched(enriched_db, url):
                logger.info(f"Skipping already enriched: {url}")
                skipped += 1
                continue

            logger.info(f"\n{'='*60}")
            logger.info(f"Enriching [{processed+1}/{len(raw_urls)}]: {url}")
            logger.info(f"Source: {source_feed}")

            # Enrich the URL
            enriched = enrich_url(url, source_feed, source_id, existing_data)

            # Insert into database
            insert_enriched_data(enriched_db, enriched)

            processed += 1
            logger.info(f"✓ Successfully enriched: {url}")

            # Small delay to be nice to services
            time.sleep(0.5)

        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")
            break
        except Exception as e:
            logger.error(f"✗ Failed to enrich {url}: {e}", exc_info=True)
            failed += 1
            continue

    logger.info(f"\n{'='*60}")
    logger.info("Enrichment pipeline completed")
    logger.info(f"Processed: {processed}")
    logger.info(f"Skipped: {skipped}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Total: {len(raw_urls)}")

    return 0


if __name__ == "__main__":
    exit(main())
