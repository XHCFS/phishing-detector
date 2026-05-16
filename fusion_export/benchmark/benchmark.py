#!/usr/bin/env python3
"""
Comprehensive fusion-model benchmark.

Covers 16 attack vectors + 8 benign categories.
Each vector has a parametric generator — same seed = same cases (regression),
new seed = fresh generation (generalization check).

Usage:
  # Full run, save baseline
  python benchmark.py --save-baseline

  # Regression check against saved baseline
  python benchmark.py --check-regression

  # Fresh generation with new seed (generalization)
  python benchmark.py --seed 1337

  # Quick smoke test (fewer cases per vector)
  python benchmark.py --n-per-vector 5
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT / "fusion_export" / "models"
BENCHMARK_DIR = Path(__file__).resolve().parent
BASELINE_PATH = BENCHMARK_DIR / "regression_baseline.json"
REPORTS_DIR = BENCHMARK_DIR / "reports"

sys.path.insert(0, str(ROOT / "fusion_export"))

from fusion_kit.operational import enrichment_to_operational_row  # noqa: E402
from fusion_kit.enrich import _SHORTENER_APEXES  # noqa: E402
from fusion_kit.scoring import (  # noqa: E402
    fusion,
    load_operational_bundle,
    score_operational,
    score_url_hash,
)

# ---------------------------------------------------------------------------
# Mock EnrichmentData builder (no live network calls)
# ---------------------------------------------------------------------------

def _make_ed(**kw):
    """Create a minimal mock EnrichmentData from keyword args."""
    from fusion_kit.enrich import EnrichmentData
    ed = EnrichmentData()
    for k, v in kw.items():
        setattr(ed, k, v)
    return ed


# ---------------------------------------------------------------------------
# Attack-vector test-case generators
# ---------------------------------------------------------------------------

def _rng_str(rng: np.random.Generator, chars: str, length: int) -> str:
    return "".join(rng.choice(list(chars), size=length))


def _alpha(rng, n): return _rng_str(rng, "abcdefghijklmnopqrstuvwxyz", n)
def _alnum(rng, n): return _rng_str(rng, "abcdefghijklmnopqrstuvwxyz0123456789", n)
def _hex(rng, n):   return _rng_str(rng, "0123456789abcdef", n)


_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "bankofamerica", "chase"]
_TLDS_LEGIT = [".com", ".org", ".net", ".co.uk"]
_TLDS_SUSPICIOUS = [".xyz", ".top", ".ru", ".cn", ".pw", ".cc", ".tk"]
_TLDS_NEW = [".zip", ".mov", ".phish", ".click", ".link"]
_RU_EU_COUNTRIES = ["RU", "UA", "BG", "RO", "MD", "KZ"]

_RECENT_CERT = "2026-04-01T00:00:00+00:00"
_NEW_DOMAIN   = "2026-04-15T00:00:00+00:00"
_OLD_DOMAIN   = "2012-03-10T00:00:00+00:00"
_OLD_CERT_FROM = "2012-01-01T00:00:00+00:00"
_OLD_CERT_TO   = "2015-01-01T00:00:00+00:00"


def gen_subdomain_chain(rng: np.random.Generator, n: int) -> list[dict]:
    """login.microsoft.com.account-verify.<random>.net — brand in subdomain labels."""
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        apex = f"{_alnum(rng,6)}.{rng.choice(['net','xyz','top','ru'])}"
        host = f"login.{brand}.com.account-verify.{apex}"
        url  = f"https://{host}/signin"
        cases.append(dict(
            url=url, host=host, domain=apex, tld=f".{apex.split('.')[-1]}",
            page_title="", ssl="yes", creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="subdomain_chain",
        ))
    return cases


def gen_numeric_domain(rng: np.random.Generator, n: int) -> list[dict]:
    """m.3011662.com style."""
    cases = []
    for _ in range(n):
        num   = int(rng.integers(100000, 9999999))
        tld   = rng.choice(["com", "net", "xyz", "top"])
        apex  = f"{num}.{tld}"
        host  = f"m.{apex}"
        url   = f"http://{host}/login"
        cases.append(dict(
            url=url, host=host, domain=apex, tld=f".{tld}",
            page_title="", ssl="no", creation_date=_NEW_DOMAIN,
            cert_from=None, cert_to=None,
            country="US", asn=None, label=1,
            vector="numeric_domain",
        ))
    return cases


def gen_new_tld(rng: np.random.Generator, n: int) -> list[dict]:
    """.zip / .mov domains used as phishing lures."""
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        tld   = rng.choice(_TLDS_NEW)
        host  = f"secure-{brand}-login{tld}"
        url   = f"https://{host}/verify"
        cases.append(dict(
            url=url, host=host, domain=host, tld=tld,
            page_title=f"{brand.capitalize()} — Verify Your Account", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="new_tld",
        ))
    return cases


def gen_char_substitution(rng: np.random.Generator, n: int) -> list[dict]:
    """micros0ft.com, g00gle.com etc."""
    _subs = {
        "paypal":       ["paypa1", "paypai", "paypa|"],
        "microsoft":    ["micros0ft", "microsofit", "mlcrosoft"],
        "google":       ["g00gle", "g0ogle", "googIe"],
        "apple":        ["appIe", "app1e", "aople"],
        "amazon":       ["arnazon", "amaz0n", "amazom"],
        "bankofamerica":["bankofamer1ca", "bankofam3rica", "bankofamerlca"],
        "chase":        ["chas3", "chasse", "chaze"],
    }
    cases = []
    brands = list(_subs.keys())
    for _ in range(n):
        brand = brands[int(rng.integers(0, len(brands)))]
        variants = _subs[brand]
        typo = variants[int(rng.integers(0, len(variants)))]
        tld  = rng.choice(["com", "net", "org"])
        host = f"{typo}.{tld}"
        url  = f"https://{host}/login"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title=f"{brand.capitalize()} — Sign In", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="char_substitution",
        ))
    return cases


def gen_idn_homograph(rng: np.random.Generator, n: int) -> list[dict]:
    """xn--pypal-4ve.com style punycode phishing."""
    _idns = [
        ("xn--pypal-4ve.com", "paypal"),      # ρaypal
        ("xn--gogle-goa.com", "google"),       # gооgle (Cyrillic o)
        ("xn--pple-43d.com",  "apple"),        # аpple (Cyrillic a)
        ("xn--micosoft-8xa.com", "microsoft"), # miсrosoft (Cyrillic c)
        ("xn--amaz0n-q2a.com", "amazon"),
        ("xn--chse-0ha.com",   "chase"),
    ]
    cases = []
    for _ in range(n):
        pair = _idns[int(rng.integers(0, len(_idns)))]
        host, brand = pair
        url = f"https://{host}/login"
        cases.append(dict(
            url=url, host=host, domain=host, tld=".com",
            page_title=f"{brand.capitalize()} — Sign In", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="idn_homograph",
        ))
    return cases


def gen_dga(rng: np.random.Generator, n: int) -> list[dict]:
    """Random-looking DGA domains."""
    _dga_tlds = ["top", "xyz", "cc", "tk", "pw", "ru", "cn"]
    cases = []
    for _ in range(n):
        length = int(rng.integers(7, 14))
        stem   = _alnum(rng, length)
        tld    = rng.choice(_dga_tlds)
        host   = f"{stem}.{tld}"
        url    = f"http://{host}/"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title="", ssl="no",
            creation_date=_NEW_DOMAIN,
            cert_from=None, cert_to=None,
            country=rng.choice(_RU_EU_COUNTRIES), asn=None, label=1,
            vector="dga",
        ))
    return cases


def gen_brand_mismatch(rng: np.random.Generator, n: int) -> list[dict]:
    """Innocent domain name, brand phishing page title."""
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        stem  = _alpha(rng, int(rng.integers(8, 16)))
        tld   = rng.choice(["com", "net", "org", "co.uk"])
        host  = f"www.{stem}.{tld}"
        url   = f"https://{host}/"
        cases.append(dict(
            url=url, host=host, domain=f"{stem}.{tld}", tld=f".{tld.split('.')[-1]}",
            page_title=f"{brand.capitalize()} — Log In", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="brand_mismatch",
        ))
    return cases


def gen_compromised_legit(rng: np.random.Generator, n: int) -> list[dict]:
    """Old legit site compromised — form submits to attacker domain."""
    _attacker_apexes = ["steal-creds.xyz", "harvest99.ru", "exfil-hub.cc",
                        "credential-dump.top", "phish-collector.pw"]
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        stem  = _alpha(rng, int(rng.integers(8, 18)))
        tld   = rng.choice(["com", "co.uk", "org", "net"])
        host  = f"www.{stem}.{tld}"
        attacker = rng.choice(_attacker_apexes)
        cases.append(dict(
            url=f"https://{host}/wp-content/uploads/verify.html",
            host=host, domain=f"{stem}.{tld}", tld=f".{tld.split('.')[-1]}",
            page_title=f"{brand.capitalize()} — Secure Login", ssl="yes",
            creation_date=_OLD_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="GB" if "co.uk" in tld else "US", asn=None,
            form_action_domain=attacker, label=1,
            vector="compromised_legit",
        ))
    return cases


def gen_platform_phishing(rng: np.random.Generator, n: int) -> list[dict]:
    """Brand-keyword subdomain on legit hosting platform."""
    _platforms = [
        ("web.app",       "Firebase"),
        ("vercel.app",    "Vercel"),
        ("netlify.app",   "Netlify"),
        ("github.io",     "GitHub Pages"),
        ("blogspot.com",  "Blogspot"),
        ("pages.dev",     "Cloudflare Pages"),
        ("glitch.me",     "Glitch"),
    ]
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        suffix = _alnum(rng, 6)
        plat_apex, plat_name = _platforms[int(rng.integers(0, len(_platforms)))]
        host = f"{brand}-secure-{suffix}.{plat_apex}"
        url  = f"https://{host}/login"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{plat_apex.split('.')[-1]}",
            page_title=f"{brand.capitalize()} — Sign In", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=13335, label=1,    # Cloudflare CDN
            vector="platform_phishing",
        ))
    return cases


def gen_api_style(rng: np.random.Generator, n: int) -> list[dict]:
    """api.paypal-account-verify.io — API-style phishing."""
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        action = rng.choice(["verify", "confirm", "validate", "secure", "authenticate"])
        tld  = rng.choice(["io", "xyz", "top", "cc"])
        apex = f"{brand}-account-{action}.{tld}"
        host = f"api.{apex}"
        url  = f"https://{host}/v1/auth"
        cases.append(dict(
            url=url, host=host, domain=apex, tld=f".{tld}",
            page_title="", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="api_style",
        ))
    return cases


def gen_zero_day_no_title(rng: np.random.Generator, n: int) -> list[dict]:
    """0-day phishing pages that return no title (JS-rendered or brand-new)."""
    cases = []
    for _ in range(n):
        stem = _alnum(rng, int(rng.integers(6, 12)))
        tld  = rng.choice(["xyz", "top", "pw", "ru"])
        host = f"{stem}.{tld}"
        url  = f"https://{host}/secure"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title="", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country=rng.choice(_RU_EU_COUNTRIES), asn=None, label=1,
            vector="zero_day_no_title",
        ))
    return cases


def gen_ru_eastern_eu_hosting(rng: np.random.Generator, n: int) -> list[dict]:
    """Generic phishing hosted in high-risk geo."""
    _ru_asns = [12389, 8359, 31163, 29182, 49505]
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        stem  = _alnum(rng, 10)
        tld   = rng.choice(["ru", "xyz", "cc", "com"])
        host  = f"{stem}.{tld}"
        url   = f"http://{host}/{brand}/login"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title=f"{brand.capitalize()} Login",
            ssl="no", creation_date=_NEW_DOMAIN,
            cert_from=None, cert_to=None,
            country=rng.choice(_RU_EU_COUNTRIES),
            asn=rng.choice(_ru_asns), label=1,
            vector="ru_eastern_eu_hosting",
        ))
    return cases


def gen_non_standard_port(rng: np.random.Generator, n: int) -> list[dict]:
    """Phishing on non-standard port :8443 / :8080."""
    _ports = [8443, 8080, 4443, 9090, 8888]
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        stem  = _alnum(rng, 8)
        tld   = rng.choice(["com", "xyz", "top"])
        port  = rng.choice(_ports)
        host  = f"{stem}.{tld}"
        url   = f"https://{host}:{port}/{brand}/login"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title=f"{brand.capitalize()} — Log In",
            ssl="yes", creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="non_standard_port",
        ))
    return cases


def gen_redirect_injection(rng: np.random.Generator, n: int) -> list[dict]:
    """OAuth redirect injection: evil ?redirect_uri= pointing to attacker."""
    _legit_hosts = ["accounts.google.com", "login.microsoftonline.com",
                    "login.salesforce.com", "auth.slack.com"]
    cases = []
    for _ in range(n):
        # The attacker-controlled redirect
        attacker = f"{_alnum(rng,8)}.{rng.choice(['xyz','pw','ru','top'])}"
        host     = rng.choice(_legit_hosts)
        url      = f"https://{host}/oauth2/authorize?client_id=abc&redirect_uri=https://{attacker}/steal"
        # Surface URL scores on the legit host — this is a KNOWN FP/limitation
        # but parametric variation helps measure edge cases
        cases.append(dict(
            url=url, host=host, domain=".".join(host.split(".")[-2:]),
            tld=".com",
            page_title="", ssl="yes",
            creation_date=_OLD_DOMAIN,
            cert_from=_OLD_CERT_FROM, cert_to=_OLD_CERT_TO,
            country="US", asn=15169, label=1,
            vector="redirect_injection",
            _known_limitation=True,  # model scores on surface URL = legit host; FN expected
        ))
    return cases


def gen_discord_crypto_scam(rng: np.random.Generator, n: int) -> list[dict]:
    """Discord/crypto NFT scam URLs."""
    _themes = ["nft", "airdrop", "claim", "mint", "wallet", "crypto", "defi"]
    cases = []
    for _ in range(n):
        theme = rng.choice(_themes)
        stem  = f"{theme}-{_alnum(rng, 6)}"
        tld   = rng.choice(["xyz", "io", "com", "app"])
        host  = f"{stem}.{tld}"
        url   = f"https://{host}/connect-wallet"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{tld}",
            page_title="Connect Your Wallet — Claim Free NFT",
            ssl="yes", creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=13335, label=1,
            vector="discord_crypto_scam",
        ))
    return cases


def gen_base64_redirect(rng: np.random.Generator, n: int) -> list[dict]:
    """click.evil.com/track?url=base64(phishing_url) — KNOWN LIMITATION."""
    import base64
    _trackers = ["click.evil-redirector.com", "track.mailblast.xyz", "email.spam-clicks.ru"]
    cases = []
    for _ in range(n):
        brand = rng.choice(_BRANDS)
        payload = f"https://phishing-{brand}.xyz/{_alnum(rng,8)}/login"
        b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        tracker = rng.choice(_trackers)
        url = f"https://{tracker}/track?url={b64}"
        cases.append(dict(
            url=url, host=tracker, domain=".".join(tracker.split(".")[-2:]),
            tld=f".{tracker.split('.')[-1]}",
            page_title="", ssl="yes",
            creation_date=_NEW_DOMAIN,
            cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=None, label=1,
            vector="base64_redirect",
            _known_limitation=True,  # payload invisible without decoding
        ))
    return cases


# ---- Benign generators ----

def gen_benign_brand_auth(rng: np.random.Generator, n: int) -> list[dict]:
    """Real brand login/auth URLs — must not be FPs.

    Cert dates use _RECENT_CERT (not _OLD_CERT_FROM/_OLD_CERT_TO): legitimate brand sites
    always renew certs; using 2012-2015 expired certs was an unrealistic artifact that
    made these indistinguishable from compromised domains.
    """
    _auth_urls = [
        ("accounts.google.com", "accounts.google.com", ".com",
         "Sign in - Google Accounts", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 15169),
        ("login.microsoftonline.com", "microsoftonline.com", ".com",
         "Sign in to your account", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 8075),
        ("www.paypal.com", "paypal.com", ".com",
         "Log in to your PayPal account", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 16509),
        ("appleid.apple.com", "apple.com", ".com",
         "Apple ID", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 714),
        ("secure.bankofamerica.com", "bankofamerica.com", ".com",
         "Bank of America — Online Banking", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 16509),
        ("auth.chase.com", "chase.com", ".com",
         "Chase — Sign in to Online Banking", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 16509),
        ("www.amazon.com", "amazon.com", ".com",
         "Amazon.com Sign-In", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 16509),
        ("login.live.com", "live.com", ".com",
         "Sign in to your Microsoft account", _OLD_DOMAIN, _RECENT_CERT, "2026-07-01T00:00:00+00:00", 8075),
    ]
    cases = []
    for _ in range(n):
        host, domain, tld, title, cd, cf, ct, asn = _auth_urls[int(rng.integers(0, len(_auth_urls)))]
        path = rng.choice(["/signin", "/login", "/auth", "/oauth2/authorize", "/security"])
        url  = f"https://{host}{path}"
        cases.append(dict(
            url=url, host=host, domain=domain, tld=tld,
            page_title=title, ssl="yes",
            creation_date=cd, cert_from=cf, cert_to=ct,
            country="US", asn=asn, label=0,
            vector="benign_brand_auth",
        ))
    return cases


def gen_benign_enterprise(rng: np.random.Generator, n: int) -> list[dict]:
    """Enterprise SSO, corporate tools."""
    _tools = [
        ("company.okta.com", "okta.com", ".com", "Okta Sign In", 16509),
        ("myorg.auth0.com",  "auth0.com", ".com", "Log in | Auth0", 16509),
        ("zoom.us",          "zoom.us",   ".us",  "Zoom — Sign In", 16509),
        ("slack.com",        "slack.com", ".com", "Sign in to Slack", 54113),
        ("login.salesforce.com", "salesforce.com", ".com", "Salesforce", 16509),
        ("portal.azure.com", "azure.com", ".com", "Microsoft Azure", 8075),
        ("dashboard.stripe.com", "stripe.com", ".com", "Stripe Dashboard", 16509),
    ]
    cases = []
    for _ in range(n):
        host, domain, tld, title, asn = _tools[int(rng.integers(0, len(_tools)))]
        url = f"https://{host}/login"
        cases.append(dict(
            url=url, host=host, domain=domain, tld=tld,
            page_title=title, ssl="yes",
            creation_date=_OLD_DOMAIN, cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=asn, label=0,
            vector="benign_enterprise",
        ))
    return cases


def gen_benign_cdn_delivery(rng: np.random.Generator, n: int) -> list[dict]:
    """CDN delivery hosts — no brand phishing meaning.

    Cert dates use _RECENT_CERT: Akamai, CloudFront, Fastly, and Google all
    rotate TLS certs on the standard 90-day automated renewal cycle.
    """
    _cdns = [
        ("cdn.akamaized.net",   "akamaized.net",  ".net",  20940),
        ("d1234.cloudfront.net","cloudfront.net", ".net",  16509),
        ("static.fastly.com",  "fastly.com",      ".com",  54113),
        ("ajax.googleapis.com","googleapis.com",  ".com",  15169),
    ]
    cases = []
    for _ in range(n):
        host, domain, tld, asn = _cdns[int(rng.integers(0, len(_cdns)))]
        url = f"https://{host}/assets/bundle.js"
        cases.append(dict(
            url=url, host=host, domain=domain, tld=tld,
            page_title="", ssl="yes",
            creation_date=_OLD_DOMAIN, cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=asn, label=0,
            vector="benign_cdn_delivery",
        ))
    return cases


def gen_benign_platform_legit(rng: np.random.Generator, n: int) -> list[dict]:
    """Legitimate Firebase/Vercel/GitHub Pages/Netlify with NO brand name.

    WHOIS on these subdomains resolves the *apex* domain (web.app, vercel.app)
    which is registered by Google/Vercel and is years old — NOT the project's
    deploy date.  Use _OLD_DOMAIN to reflect realistic WHOIS output.
    """
    _plat = [
        ("web.app",      13335),
        ("vercel.app",   16509),
        ("netlify.app",  54113),
        ("github.io",    36459),
        ("pages.dev",    13335),
    ]
    _prefixes = ["my-project", "portfolio", "team-tracker", "docs-site",
                 "blog-starter", "internal-tools", "crm-demo", "analytics",
                 "open-source", "developer-portfolio"]
    cases = []
    for _ in range(n):
        prefix = rng.choice(_prefixes) + f"-{_alnum(rng,4)}"
        plat_apex, asn = _plat[int(rng.integers(0, len(_plat)))]
        host = f"{prefix}.{plat_apex}"
        url  = f"https://{host}/"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{plat_apex.split('.')[-1]}",
            page_title="Dashboard", ssl="yes",
            # apex domain was registered years ago by platform provider (Google, Vercel, etc.)
            creation_date=_OLD_DOMAIN, cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=asn, label=0,
            vector="benign_platform_legit",
        ))
    return cases


def gen_benign_old_typosquat_parked(rng: np.random.Generator, n: int) -> list[dict]:
    """Old parked typosquat that predates the brand — not an active threat."""
    _old_squats = [
        ("gogle.com",      "gogle.com",      ".com",  "Parked Domain"),
        ("facebok.com",    "facebok.com",    ".com",  ""),
        ("twittter.com",   "twittter.com",   ".com",  ""),
        ("microsooft.com", "microsooft.com", ".com",  "Domain for Sale"),
        ("youtubbe.com",   "youtubbe.com",   ".com",  ""),
    ]
    cases = []
    for _ in range(n):
        host, domain, tld, title = _old_squats[int(rng.integers(0, len(_old_squats)))]
        url = f"https://{host}/"
        cases.append(dict(
            url=url, host=host, domain=domain, tld=tld,
            page_title=title, ssl="no",
            creation_date=_OLD_DOMAIN,
            cert_from=_OLD_CERT_FROM, cert_to=_OLD_CERT_TO,
            country="US", asn=None, label=0,
            vector="benign_old_typosquat_parked",
        ))
    return cases


def gen_benign_security_tools(rng: np.random.Generator, n: int) -> list[dict]:
    """HaveIBeenPwned, VirusTotal — complex URLs that look suspicious."""
    _sec = [
        ("haveibeenpwned.com", "haveibeenpwned.com", ".com", "Have I Been Pwned"),
        ("virustotal.com",     "virustotal.com",     ".com", "VirusTotal"),
        ("shodan.io",          "shodan.io",          ".io",  "Shodan"),
        ("urlscan.io",         "urlscan.io",          ".io",  "urlscan.io"),
    ]
    cases = []
    for _ in range(n):
        host, domain, tld, title = _sec[int(rng.integers(0, len(_sec)))]
        url = f"https://{host}/account/test@example.com"
        cases.append(dict(
            url=url, host=host, domain=domain, tld=tld,
            page_title=title, ssl="yes",
            creation_date=_OLD_DOMAIN, cert_from=_OLD_CERT_FROM, cert_to=_OLD_CERT_TO,
            country="US", asn=16509, label=0,
            vector="benign_security_tools",
        ))
    return cases


def gen_benign_url_shortener(rng: np.random.Generator, n: int) -> list[dict]:
    """Opaque shorteners pointing to benign destinations.

    In production the pipeline follows 3xx redirects (resolve_short_url in
    score_batch.py / serve.py) and scores the *destination* URL.  This
    benchmark vector tests the model's residual ability to classify shortener
    domains when the destination IS visible: the URL model sees the shortener
    URL character patterns AND the operational model sees the old trusted domain.

    Cert dates use _RECENT_CERT: real shortener services (bit.ly, t.co, etc.)
    renew their TLS certs on a standard 90-day cycle — not 2012-era expired certs.

    ASN mapping:
      13414 = Twitter (t.co)
      26802 = Bitly (bit.ly)
      54113 = Fastly (tinyurl.com, ow.ly, buff.ly share Fastly CDN)
    """
    _shorteners = [
        ("t.co",       13414),
        ("bit.ly",     26802),
        ("tinyurl.com", 54113),
        ("ow.ly",       54113),
        ("buff.ly",     54113),
    ]
    cases = []
    for _ in range(n):
        host, asn = _shorteners[int(rng.integers(0, len(_shorteners)))]
        code = _alnum(rng, rng.integers(5, 9))
        url  = f"https://{host}/{code}"
        cases.append(dict(
            url=url, host=host, domain=host, tld=f".{host.split('.')[-1]}",
            page_title="", ssl="yes",
            creation_date=_OLD_DOMAIN, cert_from=_RECENT_CERT, cert_to="2026-07-01T00:00:00+00:00",
            country="US", asn=asn, label=0,
            vector="benign_url_shortener",
        ))
    return cases


# ---------------------------------------------------------------------------
# All generators registry
# ---------------------------------------------------------------------------

ATTACK_GENERATORS = {
    "subdomain_chain":        gen_subdomain_chain,
    "numeric_domain":         gen_numeric_domain,
    "new_tld":                gen_new_tld,
    "char_substitution":      gen_char_substitution,
    "idn_homograph":          gen_idn_homograph,
    "dga":                    gen_dga,
    "brand_mismatch":         gen_brand_mismatch,
    "compromised_legit":      gen_compromised_legit,
    "platform_phishing":      gen_platform_phishing,
    "api_style":              gen_api_style,
    "zero_day_no_title":      gen_zero_day_no_title,
    "ru_eastern_eu_hosting":  gen_ru_eastern_eu_hosting,
    "non_standard_port":      gen_non_standard_port,
    "redirect_injection":     gen_redirect_injection,
    "discord_crypto_scam":    gen_discord_crypto_scam,
    "base64_redirect":        gen_base64_redirect,
}

BENIGN_GENERATORS = {
    "benign_brand_auth":           gen_benign_brand_auth,
    "benign_enterprise":           gen_benign_enterprise,
    "benign_cdn_delivery":         gen_benign_cdn_delivery,
    "benign_platform_legit":       gen_benign_platform_legit,
    "benign_old_typosquat_parked": gen_benign_old_typosquat_parked,
    "benign_security_tools":       gen_benign_security_tools,
    "benign_url_shortener":        gen_benign_url_shortener,
}

ALL_GENERATORS = {**ATTACK_GENERATORS, **BENIGN_GENERATORS}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _case_to_ed(case: dict) -> Any:
    return _make_ed(
        url=case["url"],
        domain=case.get("domain", ""),
        tld=case.get("tld", ""),
        hostname=case.get("host", ""),
        ip_address=None,
        asn=case.get("asn"),
        asn_name=None,
        country=case.get("country", "US"),
        country_name=None,
        ssl_enabled=case.get("ssl", "no"),
        cert_valid_from=case.get("cert_from"),
        cert_valid_to=case.get("cert_to"),
        cert_issuer="Let's Encrypt" if case.get("ssl") == "yes" else None,
        creation_date=case.get("creation_date"),
        page_title=case.get("page_title", ""),
        http_status_code=200.0 if case.get("page_title") is not None else None,
        form_action_domain=case.get("form_action_domain"),
    )


def _is_shortener_url(url: str) -> bool:
    """Return True if the URL apex domain is a known URL shortener."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        parts = host.lower().split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
        return apex in _SHORTENER_APEXES
    except Exception:
        return False


def score_cases(
    cases: list[dict],
    *,
    url_bundle: Any,
    op_clf: Any,
    op_cols: list[str],
    ref_card: dict,
    max_cat: int,
    threshold: float = 0.5,
) -> list[dict]:
    urls = [c["url"] for c in cases]
    url_p = score_url_hash(url_bundle, urls)

    rows = []
    for c in cases:
        ed = _case_to_ed(c)
        rows.append(enrichment_to_operational_row(ed, columns=op_cols))

    op_p = score_operational(op_clf, op_cols, ref_card, max_cat, rows)

    # For known URL shortener domains, the URL model scores the opaque redirect
    # code, not the destination — its signal is unreliable.  Use shortener-aware
    # fusion (10% url_p + 90% op_p) so the old trusted domain profile dominates.
    # The production pipeline resolves redirects before scoring, so this weighting
    # only matters here in the offline benchmark.
    shortener_mask = np.array([_is_shortener_url(u) for u in urls], dtype=bool)
    fus = fusion(url_p, op_p, shortener_mask=shortener_mask if shortener_mask.any() else None)

    results = []
    for c, up, oop, fp in zip(cases, url_p, op_p, fus):
        pred = 1 if fp >= threshold else 0
        results.append({
            **c,
            "url_p": float(up),
            "op_p":  float(oop),
            "fus_p": float(fp),
            "pred":  pred,
            "correct": pred == c["label"],
        })
    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_vector_metrics(results: list[dict]) -> dict[str, dict]:
    """Per-vector TP/FP/TN/FN and derived metrics."""
    from collections import defaultdict
    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        buckets[r["vector"]].append(r)

    metrics: dict[str, dict] = {}
    for vec, rows in buckets.items():
        label_1 = [r for r in rows if r["label"] == 1]
        label_0 = [r for r in rows if r["label"] == 0]
        tp = sum(1 for r in label_1 if r["pred"] == 1)
        fn = len(label_1) - tp
        tn = sum(1 for r in label_0 if r["pred"] == 0)
        fp = len(label_0) - tn
        tpr = tp / len(label_1) if label_1 else float("nan")
        fpr = fp / len(label_0) if label_0 else float("nan")
        prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        rec  = tpr
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else float("nan")
        known_lim = any(r.get("_known_limitation") for r in rows)
        metrics[vec] = dict(
            n=len(rows), tp=tp, fn=fn, tn=tn, fp=fp,
            tpr=round(tpr, 4), fpr=round(fpr, 4),
            precision=round(prec, 4), recall=round(rec, 4), f1=round(f1, 4),
            known_limitation=known_lim,
            mean_fus_p=round(float(np.mean([r["fus_p"] for r in rows])), 4),
        )
    return metrics


def compute_overall_metrics(results: list[dict]) -> dict:
    label_1 = [r for r in results if r["label"] == 1]
    label_0 = [r for r in results if r["label"] == 0]
    tp = sum(1 for r in label_1 if r["pred"] == 1)
    fn = len(label_1) - tp
    tn = sum(1 for r in label_0 if r["pred"] == 0)
    fp = len(label_0) - tn
    tpr = tp / len(label_1) if label_1 else float("nan")
    fpr = fp / len(label_0) if label_0 else float("nan")
    prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    f1   = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else float("nan")
    return dict(
        total=len(results), tp=tp, fn=fn, tn=tn, fp=fp,
        tpr=round(tpr, 4), fpr=round(fpr, 4),
        precision=round(prec, 4), recall=round(tpr, 4), f1=round(f1, 4),
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(vector_metrics: dict, overall: dict, seed: int) -> None:
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{'='*72}")
    print(f"  Fusion Phishing Detector — Benchmark Report")
    print(f"  Seed: {seed}   |   {ts}")
    print(f"{'='*72}")
    print(f"\n{'Vector':<30} {'N':>4} {'TPR':>6} {'FPR':>6} {'F1':>6} {'mean_p':>7}  {'Note'}")
    print("-" * 72)

    for vec, m in sorted(vector_metrics.items()):
        tpr_s = f"{m['tpr']:.3f}" if not np.isnan(m['tpr']) else " n/a "
        fpr_s = f"{m['fpr']:.3f}" if not np.isnan(m['fpr']) else " n/a "
        f1_s  = f"{m['f1']:.3f}"  if not np.isnan(m['f1'])  else " n/a "
        note  = "⚠ known limit" if m["known_limitation"] else ""
        flag  = ""
        if not np.isnan(m['tpr']) and m['tpr'] < 0.80 and not m["known_limitation"]:
            flag = "  ← WEAKNESS"
        elif not np.isnan(m['fpr']) and m['fpr'] > 0.10:
            flag = "  ← HIGH FPR"
        print(f"  {vec:<28} {m['n']:>4}  {tpr_s:>6} {fpr_s:>6} {f1_s:>6} {m['mean_fus_p']:>7}  {note}{flag}")

    print("-" * 72)
    print(f"\nOverall: N={overall['total']}  TPR={overall['tpr']:.4f}  FPR={overall['fpr']:.4f}"
          f"  Precision={overall['precision']:.4f}  F1={overall['f1']:.4f}")
    print(f"  TP={overall['tp']}  FN={overall['fn']}  TN={overall['tn']}  FP={overall['fp']}")


def check_regression(vector_metrics: dict, baseline_path: Path) -> bool:
    if not baseline_path.exists():
        print(f"[regression] No baseline at {baseline_path} — skipping check.")
        return True
    baseline = json.loads(baseline_path.read_text())["vector_metrics"]
    passed = True
    print("\n[regression check]")
    for vec, m in vector_metrics.items():
        if vec not in baseline:
            print(f"  NEW vector: {vec}")
            continue
        bm = baseline[vec]
        if not np.isnan(m["tpr"]) and not np.isnan(bm.get("tpr", float("nan"))):
            delta_tpr = m["tpr"] - bm["tpr"]
            if delta_tpr < -0.05:
                print(f"  REGRESSION {vec}: TPR {bm['tpr']:.3f} → {m['tpr']:.3f}  (Δ {delta_tpr:+.3f})")
                passed = False
            else:
                print(f"  OK        {vec}: TPR {bm['tpr']:.3f} → {m['tpr']:.3f}  (Δ {delta_tpr:+.3f})")
        if not np.isnan(m["fpr"]) and bm.get("fpr") is not None:
            delta_fpr = m["fpr"] - bm["fpr"]
            if delta_fpr > 0.05:
                print(f"  REGRESSION {vec}: FPR {bm['fpr']:.3f} → {m['fpr']:.3f}  (Δ +{delta_fpr:.3f})")
                passed = False
    return passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=42,
                    help="RNG seed (42=regression seed, other=fresh generation)")
    ap.add_argument("--n-per-vector", type=int, default=30,
                    help="Test cases per vector")
    ap.add_argument("--save-baseline", action="store_true",
                    help="Save this run as the regression baseline")
    ap.add_argument("--check-regression", action="store_true",
                    help="Compare against saved baseline and fail if regression detected")
    ap.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    ap.add_argument("--threshold", type=float, default=0.35,
                    help="Fusion score threshold for phishing verdict (must match production)")
    ap.add_argument("--vectors", nargs="*", default=None,
                    help="Run only these vectors (default: all)")
    args = ap.parse_args()

    url_path = args.models_dir / "url_char_lr.joblib"
    op_path  = args.models_dir / "hgb_operational.joblib"
    if not url_path.exists():
        print(f"Missing {url_path}", file=sys.stderr); return 1
    if not op_path.exists():
        print(f"Missing {op_path}", file=sys.stderr); return 1

    url_bundle = joblib.load(url_path)
    op_clf, op_cols, ref_card, max_cat = load_operational_bundle(op_path)

    generators = ALL_GENERATORS
    if args.vectors:
        generators = {k: v for k, v in ALL_GENERATORS.items() if k in args.vectors}

    rng = np.random.default_rng(args.seed)
    all_cases: list[dict] = []
    for vec, gen_fn in generators.items():
        cases = gen_fn(rng, args.n_per_vector)
        all_cases.extend(cases)

    print(f"Scoring {len(all_cases)} test cases (seed={args.seed}, n_per_vector={args.n_per_vector}) …")
    results = score_cases(
        all_cases,
        url_bundle=url_bundle,
        op_clf=op_clf, op_cols=op_cols, ref_card=ref_card, max_cat=max_cat,
        threshold=args.threshold,
    )

    vector_metrics = compute_vector_metrics(results)
    overall = compute_overall_metrics(results)
    print_report(vector_metrics, overall, args.seed)

    # Save timestamped report
    REPORTS_DIR.mkdir(exist_ok=True)
    ts_slug = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_data = {
        "seed": args.seed, "n_per_vector": args.n_per_vector,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "overall": overall, "vector_metrics": vector_metrics,
        "failures": [r for r in results if not r["correct"] and not r.get("_known_limitation")],
    }
    report_path = REPORTS_DIR / f"report_{ts_slug}_seed{args.seed}.json"
    report_path.write_text(json.dumps(report_data, indent=2))
    print(f"\nReport saved: {report_path}")

    if args.save_baseline:
        BASELINE_PATH.write_text(json.dumps({
            "seed": args.seed, "n_per_vector": args.n_per_vector,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "overall": overall, "vector_metrics": vector_metrics,
        }, indent=2))
        print(f"Baseline saved: {BASELINE_PATH}")

    if args.check_regression:
        ok = check_regression(vector_metrics, BASELINE_PATH)
        if not ok:
            print("\n[regression] FAIL — one or more regressions detected.")
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
