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

PERFORMANCE OPTIMIZATIONS:
- Async I/O for network operations (DNS, HTTP, SSL)
- Concurrent processing of multiple URLs
- Thread pool for blocking operations (WHOIS, IPWhois)
- Batch database inserts
- Connection pooling for GeoIP databases
"""

import ssl
import socket
import sqlite3
import time
import argparse
import asyncio
import warnings
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import logging

# Suppress all warnings from libraries (urllib3, SSL, etc.)
warnings.filterwarnings('ignore')

# Disable ALL logging from noisy libraries (must be done BEFORE imports)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').propagate = False
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('requests').propagate = False
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').propagate = False
logging.getLogger('aiohttp').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp').propagate = False
logging.getLogger('aiohttp.client').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.client').propagate = False
logging.getLogger('aiohttp.server').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.server').propagate = False
logging.getLogger('aiohttp.access').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.access').propagate = False

# Set global socket timeout for DNS operations (performance boost)
socket.setdefaulttimeout(0.5)  # Even more aggressive!

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
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    # Not critical - we have requests fallback

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

# Configure logging (WARNING level for performance - no INFO/DEBUG spam)
logging.basicConfig(
    level=logging.WARNING,
    format='%(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database paths
DB_DIR = Path(__file__).parent
RAW_DB_PATH = DB_DIR / "threat_feeds_raw.db"
ENRICHED_DB_PATH = DB_DIR / "threat_feeds.db"

# GeoIP database paths (MaxMind GeoLite2)
GEOIP_CITY_DB = DB_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_DB = DB_DIR / "GeoLite2-ASN.mmdb"

# Rate limiting and timeouts (HYPER-AGGRESSIVE - LUDICROUS SPEED)
WHOIS_DELAY = 0.0  # No delays
DNS_TIMEOUT = 0.5  # Very aggressive
SSL_TIMEOUT = 1.0  # Very aggressive
HTTP_TIMEOUT = 1.5  # Very aggressive
MAX_RETRIES = 0  # No retries

# Concurrency settings (MAXIMUM PARALLELISM)
MAX_CONCURRENT_URLS = 100  # Doubled for max throughput
MAX_WORKER_THREADS = 200  # Doubled for max parallelism
BATCH_INSERT_SIZE = 200  # Doubled for fewer DB operations

# Global caches for performance
_geoip_city_reader = None
_geoip_asn_reader = None
_http_session = None  # Reusable requests session
_dns_cache = {}  # DNS resolution cache for repeated domains

# Pre-compile commonly used regex patterns (HUGE speedup)
_TITLE_REGEX = re.compile(
    r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
_LANG_REGEX = re.compile(
    r'<html[^>]+lang=["\']([^"\']+)["\']', re.IGNORECASE)


def get_geoip_city_reader():
    """Get cached GeoIP City reader."""
    global _geoip_city_reader
    if _geoip_city_reader is None and GEOIP_AVAILABLE and GEOIP_CITY_DB.exists():
        _geoip_city_reader = geoip2.database.Reader(str(GEOIP_CITY_DB))
    return _geoip_city_reader


def get_geoip_asn_reader():
    """Get cached GeoIP ASN reader."""
    global _geoip_asn_reader
    if _geoip_asn_reader is None and GEOIP_AVAILABLE and GEOIP_ASN_DB.exists():
        _geoip_asn_reader = geoip2.database.Reader(str(GEOIP_ASN_DB))
    return _geoip_asn_reader


def get_http_session():
    """Get cached HTTP session with aggressive connection pooling."""
    global _http_session
    if _http_session is None and REQUESTS_AVAILABLE:
        _http_session = requests.Session()
        # ULTRA AGGRESSIVE connection pooling for max performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=500,  # 5x increase
            pool_maxsize=500,  # 5x increase
            max_retries=0,
            pool_block=False  # Don't block when pool full
        )
        _http_session.mount('http://', adapter)
        _http_session.mount('https://', adapter)
    return _http_session


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
    """Extract domain from URL (optimized)."""
    try:
        # Fast path: if already parsed, avoid re-parsing
        if not url:
            return None
        parsed = urlparse(url if url.startswith(
            'http') else f'http://{url}')
        return parsed.hostname
    except Exception:
        return None


def extract_tld(domain: str) -> Optional[str]:
    """Extract TLD from domain (fast path)."""
    if not domain:
        return None
    # Fast string operation instead of split
    last_dot = domain.rfind('.')
    return domain[last_dot:] if last_dot != -1 else None


def resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address (with caching for speed)."""
    if not domain:
        return None
    
    # Check cache first (HUGE speedup for repeated domains)
    if domain in _dns_cache:
        return _dns_cache[domain]
    
    try:
        ip = socket.gethostbyname(domain)
        _dns_cache[domain] = ip  # Cache result
        return ip
    except (socket.gaierror, socket.timeout):
        _dns_cache[domain] = None  # Cache failures too
        return None


async def resolve_ip_async(domain: str) -> Optional[str]:
    """Async DNS resolution."""
    if not domain:
        return None
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(
            domain, None, family=socket.AF_INET,
            type=socket.SOCK_STREAM
        )
        if result:
            return result[0][4][0]
        return None
    except (socket.gaierror, socket.timeout, OSError):
        return None


def extract_base_domain(domain: str) -> str:
    """Extract base domain from subdomain."""
    if not domain:
        return domain
    
    # Multi-level TLDs like .co.uk, .ac.in, etc.
    multi_level_tlds = [
        '.co.uk', '.ac.uk', '.gov.uk', '.org.uk',
        '.co.in', '.ac.in', '.gov.in',
        '.co.jp', '.ac.jp', '.go.jp',
        '.com.au', '.gov.au', '.edu.au',
        '.co.nz', '.govt.nz', '.ac.nz',
    ]
    
    domain_lower = domain.lower()
    for tld in multi_level_tlds:
        if domain_lower.endswith(tld):
            # Get the part before this TLD
            prefix = domain[:-(len(tld))]
            # Split the prefix and take the last part
            if '.' in prefix:
                base_name = prefix.rsplit('.', 1)[-1]
                return base_name + tld
            # No subdomain, return as is
            return domain
    
    # Standard TLD case (e.g., .com, .org, .net)
    parts = domain.split('.')
    if len(parts) > 2:
        # Return last two parts (example.com from mail.example.com)
        return '.'.join(parts[-2:])
    
    return domain


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for domain (extracts base domain first)."""
    if not WHOIS_AVAILABLE or not domain:
        return {}

    try:
        # Extract base domain for WHOIS (subdomain WHOIS queries fail)
        base_domain = extract_base_domain(domain)
        
        # No artificial delay - thread pool provides natural rate limiting
        w = whois.whois(base_domain)

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
    except Exception:
        return {}


def get_geoip_info(ip_address: str) -> Dict[str, Any]:
    """Get GeoIP information for IP address (using cached readers)."""
    if not ip_address:
        return {}

    result = {}

    # Try GeoIP databases if available (use cached readers for speed)
    if GEOIP_AVAILABLE:
        # Try City database
        city_reader = get_geoip_city_reader()
        if city_reader:
            try:
                response = city_reader.city(ip_address)
                result.update({
                    'country': response.country.iso_code,
                    'country_name': response.country.name,
                    'region': response.subdivisions.most_specific.name
                    if response.subdivisions else None,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                })
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

        # Try ASN database
        asn_reader = get_geoip_asn_reader()
        if asn_reader:
            try:
                response = asn_reader.asn(ip_address)
                result.update({
                    'asn': response.autonomous_system_number,
                    'asn_name': response.autonomous_system_organization,
                })
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

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
        except Exception:
            pass

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
    except Exception:
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
    except (socket.timeout, ssl.SSLError, Exception):
        return {'ssl_enabled': 'no'}


async def get_ssl_info_async(domain: str) -> Dict[str, Any]:
    """Async SSL certificate check."""
    if not domain:
        return {}
    
    try:
        loop = asyncio.get_event_loop()
        # Run blocking SSL check in thread pool
        return await loop.run_in_executor(None, get_ssl_info, domain)
    except Exception:
        return {'ssl_enabled': 'no'}


def get_page_content(url: str) -> Dict[str, Any]:
    """Get page content including title and language (uses cached session)."""
    if not REQUESTS_AVAILABLE or not url:
        return {}

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        session = get_http_session()
        if not session:
            return {}
        
        response = session.get(
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

        # ULTRA FAST: Use regex instead of BS4 (10x faster for simple parsing)
        # BeautifulSoup is overkill for just extracting title and lang
        title_match = _TITLE_REGEX.search(response.text)
        if title_match:
            result['page_title'] = title_match.group(1).strip()[:200]

        lang_match = _LANG_REGEX.search(response.text)
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
    except Exception:
        return {'online': 'unknown', 'http_status_code': None}


def check_online_status(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Check if URL is online and get HTTP status (lightweight HEAD request)."""
    if not REQUESTS_AVAILABLE or not url:
        return None, None

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        session = get_http_session()
        if not session:
            return None, None
        
        response = session.head(
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
    except Exception:
        return 'unknown', None


async def check_online_status_async(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Async online status check (ULTRA fast with aggressive timeouts)."""
    if not url:
        return None, None
    
    # Use aiohttp if available for true async
    if AIOHTTP_AVAILABLE:
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            # ULTRA aggressive timeout
            timeout = aiohttp.ClientTimeout(
                total=HTTP_TIMEOUT,
                connect=0.5,  # Fast connection timeout
                sock_read=0.5  # Fast read timeout
            )
            # Reuse connector for better performance
            connector = aiohttp.TCPConnector(
                limit=200,  # High connection limit
                ttl_dns_cache=300,  # Cache DNS for 5 min
                force_close=False,  # Keep connections alive
                enable_cleanup_closed=True
            )
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            ) as session:
                async with session.head(
                    url,
                    allow_redirects=True,
                    ssl=False  # Skip SSL verification
                ) as response:
                    return 'yes', response.status
        except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
            # Fast fail - don't retry
            return 'no', None
    
    # Fallback to requests in thread pool
    if REQUESTS_AVAILABLE:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, check_online_status, url)
        except Exception:
            return 'unknown', None
    
    return None, None


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
        data.ip_address = resolve_ip(data.domain)

    # Get WHOIS information
    whois_info = get_whois_info(data.domain)
    if whois_info:
        data.registrar = whois_info.get('registrar')
        data.creation_date = whois_info.get('creation_date')
        data.expiry_date = whois_info.get('expiry_date')
        data.updated_date = whois_info.get('updated_date')
        data.name_servers = whois_info.get('name_servers')

    # Get GeoIP information
    if data.ip_address:
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
        if IPWHOIS_AVAILABLE and (not data.asn or not data.cidr_block):
            asn_info = get_asn_info_ipwhois(data.ip_address)
            if asn_info:
                data.asn = data.asn or asn_info.get('asn')
                data.asn_name = data.asn_name or asn_info.get('asn_name')
                data.cidr_block = data.cidr_block or asn_info.get(
                    'cidr_block')
                data.isp = data.isp or asn_info.get('isp')
                data.country = data.country or asn_info.get('country')

    # Get SSL certificate information
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
        page_info = get_page_content(url)
        if page_info:
            data.online = data.online or page_info.get('online')
            data.http_status_code = page_info.get('http_status_code')
            data.page_title = page_info.get('page_title')
            data.page_language = page_info.get('page_language')

    # Fallback lightweight online check if still no status
    if not data.online:
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
            except LangDetectException:
                pass
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


async def enrich_url_async(
        url: str,
        source_feed: str,
        source_id: Optional[str] = None,
        existing_data: Optional[Dict[str, Any]] = None,
        executor: Optional[ThreadPoolExecutor] = None,
        enable_whois: bool = True,  # Enabled by default
        enable_ipwhois: bool = True,  # Enabled by default
        enable_page_content: bool = True  # Enabled by default
) -> EnrichmentData:
    """
    HYPER-OPTIMIZED async enrichment with MAXIMUM parallelism.
    
    ALL network operations run in parallel - no sequential waits!
    - DNS, SSL, HTTP, WHOIS, IPWhois all start simultaneously
    - Uses async I/O where possible (aiohttp, async DNS)
    - Thread pool only for truly blocking operations (WHOIS, IPWhois)
    - Cached readers for GeoIP (no file reopening)
    """
    data = EnrichmentData()
    data.url = url
    data.source_feed = source_feed
    data.source_id = source_id

    # Extract domain (sync, instant)
    data.domain = extract_domain(url)
    if not data.domain:
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

    loop = asyncio.get_event_loop()
    
    # ========================================================================
    # PHASE 1: Start ALL operations in parallel (no waits!)
    # ========================================================================
    
    # DNS resolution (async, needed for other operations)
    dns_task = None
    if not data.ip_address:
        dns_task = resolve_ip_async(data.domain)
    
    # WHOIS lookup (blocking, in thread pool) - OPTIONAL (slow!)
    whois_task = None
    if enable_whois and WHOIS_AVAILABLE:
        whois_task = loop.run_in_executor(
            executor, get_whois_info, data.domain
        )
    
    # SSL check (async I/O) - can run independently
    ssl_task = get_ssl_info_async(data.domain)
    
    # Online check (async I/O) - can run independently
    online_task = None
    if not data.online:
        online_task = check_online_status_async(url)
    
    # Page content (title, language) - ENABLED by default (can disable)
    page_task = None
    if enable_page_content and not data.page_title:
        page_task = loop.run_in_executor(
            executor, get_page_content, url
        )
    
    # ========================================================================
    # PHASE 2: Wait for DNS first (needed for GeoIP and IPWhois)
    # ========================================================================
    
    if dns_task:
        data.ip_address = await dns_task
    
    # ========================================================================
    # PHASE 3: Start IP-dependent operations in parallel
    # ========================================================================
    
    # GeoIP lookup (sync but fast with cached readers)
    geoip_task = None
    if data.ip_address:
        # Run GeoIP in thread pool to not block event loop
        geoip_task = loop.run_in_executor(
            executor, get_geoip_info, data.ip_address
        )
    
    # IPWhois lookup (blocking, in thread pool) - OPTIONAL (can be slow!)
    ipwhois_task = None
    if (enable_ipwhois and data.ip_address and IPWHOIS_AVAILABLE and
            (not data.asn or not data.cidr_block)):
        ipwhois_task = loop.run_in_executor(
            executor, get_asn_info_ipwhois, data.ip_address
        )
    
    # ========================================================================
    # PHASE 4: Gather ALL results in parallel (asyncio.gather)
    # ========================================================================
    
    # Collect all pending tasks (build list dynamically)
    pending_tasks = []
    task_map = {}  # Track what each index represents
    
    if whois_task:
        task_map[len(pending_tasks)] = 'whois'
        pending_tasks.append(whois_task)
    
    task_map[len(pending_tasks)] = 'ssl'
    pending_tasks.append(ssl_task)
    
    if online_task:
        task_map[len(pending_tasks)] = 'online'
        pending_tasks.append(online_task)
    
    if page_task:
        task_map[len(pending_tasks)] = 'page'
        pending_tasks.append(page_task)
    
    if geoip_task:
        task_map[len(pending_tasks)] = 'geoip'
        pending_tasks.append(geoip_task)
    
    if ipwhois_task:
        task_map[len(pending_tasks)] = 'ipwhois'
        pending_tasks.append(ipwhois_task)
    
    # Wait for ALL tasks to complete in parallel
    results = await asyncio.gather(*pending_tasks, return_exceptions=True)
    
    # ========================================================================
    # PHASE 5: Process results (using task_map for correct indexing)
    # ========================================================================
    
    # Parse results based on task_map
    for idx, task_type in task_map.items():
        if idx >= len(results):
            continue
        
        result = results[idx]
        if isinstance(result, Exception):
            continue
        
        if task_type == 'whois' and result:
            data.registrar = result.get('registrar')
            data.creation_date = result.get('creation_date')
            data.expiry_date = result.get('expiry_date')
            data.updated_date = result.get('updated_date')
            data.name_servers = result.get('name_servers')
        
        elif task_type == 'ssl' and result:
            data.ssl_enabled = result.get('ssl_enabled')
            data.cert_issuer = result.get('cert_issuer')
            data.cert_subject = result.get('cert_subject')
            data.cert_valid_from = result.get('cert_valid_from')
            data.cert_valid_to = result.get('cert_valid_to')
            data.cert_serial = result.get('cert_serial')
        
        elif task_type == 'online' and result:
            data.online, data.http_status_code = result
        
        elif task_type == 'page' and result:
            data.online = data.online or result.get('online')
            data.http_status_code = (data.http_status_code or
                                    result.get('http_status_code'))
            data.page_title = result.get('page_title')
            data.page_language = result.get('page_language')
        
        elif task_type == 'geoip' and result:
            data.country = data.country or result.get('country')
            data.country_name = result.get('country_name')
            data.region = result.get('region')
            data.city = result.get('city')
            data.latitude = result.get('latitude')
            data.longitude = result.get('longitude')
            data.asn = data.asn or result.get('asn')
            data.asn_name = result.get('asn_name')
        
        elif task_type == 'ipwhois' and result:
            data.asn = data.asn or result.get('asn')
            data.asn_name = data.asn_name or result.get('asn_name')
            data.cidr_block = data.cidr_block or result.get('cidr_block')
            data.isp = data.isp or result.get('isp')
            data.country = data.country or result.get('country')
    
    # ========================================================================
    # PHASE 6: Post-processing and inference
    # ========================================================================
    
    # Fill ISP from ASN name if not already set
    if not data.isp and data.asn_name:
        data.isp = data.asn_name
    
    # Infer threat_type from source feed if not set
    if not data.threat_type:
        if source_feed in ('phishtank', 'openphish'):
            data.threat_type = 'phishing'
        elif source_feed == 'urlhaus':
            data.threat_type = 'malware'
    
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


def insert_enriched_data_batch(
        enriched_db_path: Path,
        data_list: List[EnrichmentData]
):
    """Batch insert enriched data with ULTRA performance optimizations."""
    if not data_list:
        return
    
    con = sqlite3.connect(str(enriched_db_path))
    
    # ULTRA PERFORMANCE: Enable WAL mode and aggressive pragmas
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL
    con.execute("PRAGMA cache_size=100000")  # 100MB cache
    con.execute("PRAGMA temp_store=MEMORY")  # Use memory for temp
    
    cur = con.cursor()
    
    # Prepare all records
    records = []
    for data in data_list:
        records.append((
            data.url, data.domain, data.online, data.http_status_code,
            data.ip_address, data.cidr_block, data.asn, data.asn_name,
            data.isp, data.country, data.country_name, data.region,
            data.city, data.latitude, data.longitude,
            data.ssl_enabled, data.cert_issuer, data.cert_subject,
            data.cert_valid_from, data.cert_valid_to, data.cert_serial,
            data.tld, data.registrar, data.creation_date, data.expiry_date,
            data.updated_date, data.name_servers,
            data.page_language, data.page_title,
            data.threat_type, data.target_brand, data.threat_tags,
            data.source_feed, data.source_id, data.last_seen,
            data.notes
        ))
    
    # Batch insert
    cur.executemany("""
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
    """, records)
    
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


def check_already_enriched_batch(
        enriched_db_path: Path,
        urls: List[str]
) -> Dict[str, bool]:
    """Batch check if URLs are already enriched (optimized for speed)."""
    if not urls:
        return {}
    
    con = sqlite3.connect(str(enriched_db_path))
    
    # Performance optimizations
    con.execute("PRAGMA cache_size=50000")
    con.execute("PRAGMA temp_store=MEMORY")
    
    cur = con.cursor()
    
    # Use IN clause for batch query
    placeholders = ','.join('?' * len(urls))
    cur.execute(
        f"SELECT url FROM enriched_threats WHERE url IN ({placeholders})",
        urls
    )
    
    enriched_urls = {row[0] for row in cur.fetchall()}
    cur.close()
    con.close()
    
    # Return dict of url -> is_enriched
    return {url: (url in enriched_urls) for url in urls}


async def process_batch_async(
        batch: List[Tuple[str, str, Optional[str], Dict[str, Any]]],
        enriched_db: Path,
        skip_existing: bool,
        executor: ThreadPoolExecutor,
        enable_whois: bool = True,
        enable_ipwhois: bool = True,
        enable_page_content: bool = True
) -> Tuple[int, int, int]:
    """
    Process a batch of URLs concurrently.
    
    Returns: (processed, skipped, failed) counts
    """
    processed = 0
    skipped = 0
    failed = 0
    
    enriched_data_list = []
    
    # Batch check for existing URLs (MUCH faster than one-by-one)
    enriched_status = {}
    if skip_existing:
        all_urls = [url for url, _, _, _ in batch]
        loop = asyncio.get_event_loop()
        enriched_status = await loop.run_in_executor(
            executor, check_already_enriched_batch, enriched_db, all_urls
        )
    
    # Create tasks for all URLs in batch
    tasks = []
    urls_to_process = []
    
    for url, source_feed, source_id, existing_data in batch:
        # Skip if already enriched (use batch result)
        if skip_existing and enriched_status.get(url, False):
            skipped += 1
            continue
        
        urls_to_process.append((url, source_feed, source_id))
        task = enrich_url_async(
            url, source_feed, source_id, existing_data, executor,
            enable_whois, enable_ipwhois, enable_page_content
        )
        tasks.append(task)
    
    # Process all URLs concurrently
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            url, source_feed, source_id = urls_to_process[i]
            
            if isinstance(result, Exception):
                failed += 1
            else:
                enriched_data_list.append(result)
                processed += 1
    
    # Batch insert all results
    if enriched_data_list:
        insert_enriched_data_batch(enriched_db, enriched_data_list)
    
    return processed, skipped, failed


async def process_all_async(
        raw_urls: List[Tuple[str, str, Optional[str], Dict[str, Any]]],
        enriched_db: Path,
        skip_existing: bool,
        max_concurrent: int = MAX_CONCURRENT_URLS,
        max_workers: int = MAX_WORKER_THREADS,
        enable_whois: bool = True,
        enable_ipwhois: bool = True,
        enable_page_content: bool = True
) -> Tuple[int, int, int]:
    """
    Process all URLs with concurrent batching.
    
    Returns: (total_processed, total_skipped, total_failed)
    """
    total_processed = 0
    total_skipped = 0
    total_failed = 0
    
    # Create thread pool for blocking operations
    executor = ThreadPoolExecutor(max_workers=max_workers)
    
    try:
        # Process in batches (silent processing for max speed)
        total_batches = (len(raw_urls) + max_concurrent - 1) // max_concurrent
        for i in range(0, len(raw_urls), max_concurrent):
            batch = raw_urls[i:i + max_concurrent]
            batch_num = (i // max_concurrent) + 1
            
            # Show progress every 10 batches or on first/last batch
            if batch_num == 1 or batch_num == total_batches or batch_num % 10 == 0:
                print(f"Processing batch {batch_num}/{total_batches}...", flush=True)
            
            processed, skipped, failed = await process_batch_async(
                batch, enriched_db, skip_existing, executor,
                enable_whois, enable_ipwhois, enable_page_content
            )
            
            total_processed += processed
            total_skipped += skipped
            total_failed += failed
    
    finally:
        executor.shutdown(wait=True)
    
    return total_processed, total_skipped, total_failed


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
    parser.add_argument(
        '--legacy',
        action='store_true',
        help='Use legacy synchronous processing (slower but simpler)'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=MAX_CONCURRENT_URLS,
        help=f'Number of URLs to process concurrently (default: {MAX_CONCURRENT_URLS})'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=MAX_WORKER_THREADS,
        help=f'Thread pool size for blocking operations (default: {MAX_WORKER_THREADS})'
    )
    parser.add_argument(
        '--disable-whois',
        action='store_true',
        help='Disable WHOIS lookups for speed (loses registrar data)'
    )
    parser.add_argument(
        '--disable-ipwhois',
        action='store_true',
        help='Disable IPWhois lookups for speed (loses CIDR data)'
    )
    parser.add_argument(
        '--disable-page-content',
        action='store_true',
        help='Disable page content fetching for speed (loses title/language)'
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

    # Use concurrency settings from CLI args (without modifying globals)
    max_concurrent = args.concurrency if args.concurrency else MAX_CONCURRENT_URLS
    max_workers = args.workers if args.workers else MAX_WORKER_THREADS

    # Choose processing mode
    if args.legacy:
        # Legacy synchronous processing
        logger.info(f"\n{'='*60}")
        logger.info("Starting LEGACY synchronous enrichment pipeline...")
        logger.warning("Using legacy mode - consider async mode for better performance")
        
        processed = 0
        skipped = 0
        failed = 0
        
        try:
            for url, source_feed, source_id, existing_data in raw_urls:
                try:
                    if args.skip_existing and check_already_enriched(enriched_db, url):
                        logger.info(f"Skipping already enriched: {url}")
                        skipped += 1
                        continue

                    logger.info(f"\n{'='*60}")
                    logger.info(f"Enriching [{processed+1}/{len(raw_urls)}]: {url}")
                    logger.info(f"Source: {source_feed}")

                    enriched = enrich_url(url, source_feed, source_id, existing_data)
                    insert_enriched_data(enriched_db, enriched)

                    processed += 1
                    logger.info(f"✓ Successfully enriched: {url}")
                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"✗ Failed to enrich {url}: {e}", exc_info=True)
                    failed += 1
                    
        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")
    else:
        # Modern async batch processing
        start_time = time.time()
        print(f"\n{'='*60}")
        print("Starting ULTRA-FAST async enrichment pipeline...")
        print(f"Concurrency: {max_concurrent} URLs per batch")
        print(f"Thread pool: {max_workers} workers")
        print(f"Batch insert: {BATCH_INSERT_SIZE} records")
        print(f"Total URLs: {len(raw_urls)}")
        
        # Show what's enabled/disabled
        whois_enabled = not args.disable_whois
        ipwhois_enabled = not args.disable_ipwhois
        page_enabled = not args.disable_page_content
        print("\nFeatures:")
        whois_status = '✓ enabled' if whois_enabled else '✗ disabled'
        ipwhois_status = '✓ enabled' if ipwhois_enabled else '✗ disabled'
        page_status = '✓ enabled' if page_enabled else '✗ disabled'
        print(f"   • WHOIS:        {whois_status}")
        print(f"   • IPWhois:      {ipwhois_status}")
        print(f"   • Page content: {page_status}")
        print(f"{'='*60}\n")
        
        try:
            processed, skipped, failed = asyncio.run(
                process_all_async(
                    raw_urls, enriched_db, args.skip_existing,
                    max_concurrent, max_workers,
                    not args.disable_whois,
                    not args.disable_ipwhois,
                    not args.disable_page_content
                )
            )
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            processed = skipped = failed = 0

    elapsed = time.time() - start_time if 'start_time' in locals() else 0
    
    # Final summary
    print(f"\n{'='*60}")
    print("Enrichment pipeline completed!")
    print(f"{'='*60}")
    print("Results:")
    print(f"   • Processed:  {processed:,}")
    print(f"   • Skipped:    {skipped:,}")
    print(f"   • Failed:     {failed:,}")
    print(f"   • Total URLs: {len(raw_urls):,}")
    if elapsed > 0:
        print("\nPerformance:")
        print(f"   • Time:       {elapsed:.1f}s")
        print(f"   • Speed:      {len(raw_urls)/elapsed:.1f} URLs/sec")
        if processed > 0:
            print(f"   • Avg/URL:    {elapsed/processed:.2f}s")
    print(f"{'='*60}\n")
    
    return 0


if __name__ == "__main__":
    exit(main())
