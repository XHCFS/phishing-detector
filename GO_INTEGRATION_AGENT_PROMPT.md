# Agent Prompt: Phishing Detector Go Integration PR

## Context

You are a senior software engineer. Your task is to create a pull request that integrates a machine-learning phishing detector into an existing Go service. You have been given:

1. **`fusion_detector_v1.9.1.zip`** — the complete Python ML package (unzip it to inspect)
2. **A Go service repo** — your working directory; you must find the right insertion points

This is a Layer 2 integration. The Go service already has a threat-intelligence feed lookup (Layer 1). Layer 2 fires **only when a URL is not found in the feed**. Your job is to build that layer.

---

## What Is In The Zip

Unzip `fusion_detector_v1.9.1.zip`. You will find:

```
fusion_export/
  fusion_kit/
    enrich.py          # Full Python enrichment pipeline (read this carefully)
    operational.py     # 44-feature extraction from enriched data (read this carefully)
    scoring.py         # Fusion logic: url_p + op_p → deploy_p
    GeoLite2-ASN.mmdb
    GeoLite2-City.mmdb
    GeoLite2-Country.mmdb
  models/
    url_char_lr.joblib      # URL character n-gram LR model
    hgb_operational.joblib  # 44-feature HGB operational model
    checksums.txt
  scripts/
    serve.py           # Python HTTP sidecar (you will modify this)
  GO_INTEGRATION.md    # Architecture reference (read this)
  requirements.txt
```

**Read `fusion_kit/enrich.py`, `fusion_kit/operational.py`, `fusion_kit/scoring.py`, and `scripts/serve.py` in full before writing any code.**

---

## Architecture

The integration has two moving parts:

### Part 1: Modified Python Sidecar (minimal change)

The existing `serve.py` does enrichment + inference in Python. You will add **one new endpoint** that accepts pre-computed feature vectors and returns only model scores. This decouples Go-side enrichment from Python-side inference.

New endpoint: `POST /score-features`

Request body:
```json
{
  "requests": [
    {
      "normalized_url": "https://example.com/login",
      "is_shortener": false,
      "features": {
        "url": "https://example.com/login",
        "hostname": "example.com",
        "domain": "example.com",
        "tld": "com",
        "ip_address": "93.184.216.34",
        "cidr_block": "93.184.216.0/24",
        "asn": 15133,
        "asn_name": "MCI Communications Services",
        "isp": "Edgecast",
        "country": "US",
        "country_name": "United States",
        "region": "California",
        "city": "Los Angeles",
        "latitude": 34.0522,
        "longitude": -118.2437,
        "ssl_enabled": "true",
        "cert_issuer": "Let's Encrypt",
        "cert_subject": "CN=example.com",
        "cert_valid_from": "2026-01-01T00:00:00+00:00",
        "cert_valid_to": "2026-04-01T00:00:00+00:00",
        "http_status_code": 200,
        "page_title": "Login",
        "page_language": "en",
        "registrar": "MarkMonitor Inc.",
        "creation_date": "1995-08-14T04:00:00+00:00",
        "expiry_date": "2025-08-13T04:00:00+00:00",
        "updated_date": "2024-08-14T07:01:34+00:00",
        "name_servers": "a.iana-servers.net,b.iana-servers.net",
        "domain_age_days": 11200.0,
        "cert_age_days": 30.0,
        "cert_validity_span_days": 90.0,
        "title_brand_mismatch": 0.0,
        "title_has_login_kw": 1.0,
        "subdomain_depth": 0.0,
        "subdomain_brand_count": 0.0,
        "apex_is_numeric": 0.0,
        "form_action_mismatch": 0.0,
        "ip_in_url": 0.0,
        "non_std_port": 0.0,
        "url_domain_char_ratio": 0.0,
        "favicon_domain_mismatch": 0.0,
        "password_field_count": 1.0,
        "has_hidden_redirect": 0.0,
        "is_ephemeral_platform": 0.0
      }
    }
  ]
}
```

Response:
```json
{
  "results": [
    {
      "url": "https://example.com/login",
      "url_p": 0.003,
      "op_p": 0.001,
      "deploy_p": 0.002,
      "verdict": "benign"
    }
  ],
  "threshold": 0.35,
  "fusion_mode": "mean"
}
```

**Implementation notes for `/score-features`:**
- `normalized_url` is passed through `score_url_hash()` unchanged (the pipeline already lowercases internally)
- `features` dict is passed through `score_operational()` as a single row — the column order and NaN handling are already handled by `score_operational()`
- Apply `fusion()` with `shortener_mask` if `is_shortener=true`
- Missing numeric feature values in the request → `float('nan')` 
- Missing string feature values → `""`
- The existing `/score` endpoint stays untouched — backward compatible

### Part 2: Go Enrichment + Client

Go implements all enrichment concurrently. Python sidecar does only inference. This is the right architecture because Go's goroutine model handles concurrent network I/O far more efficiently than Python threads.

---

## Go Package Structure

Create these packages inside the Go service. Find the correct package prefix by examining `go.mod`. Place under `internal/phishing/` (or the project's equivalent internal path):

```
internal/phishing/
  enricher/
    enricher.go        # Orchestrator: runs all steps concurrently, returns EnrichedURL
    dns.go             # DNS resolution + caching
    whois.go           # WHOIS lookup → creation_date, expiry, registrar, nameservers
    geoip.go           # MaxMind GeoIP → ASN, country, lat/lon
    tls.go             # TLS certificate → cert_valid_from, cert_valid_to, cert_issuer
    http.go            # HTTP fetch → status, title, form_action, favicon, password fields
    shortener.go       # URL shortener detection + redirect resolution
    features.go        # EnrichedURL → FeatureVector (44 fields, exact column mapping)
    enricher_test.go
    dns_test.go
    whois_test.go
    geoip_test.go
    tls_test.go
    http_test.go
    shortener_test.go
    features_test.go
  client/
    client.go          # HTTP client → calls sidecar /score-features
    cache.go           # LRU cache keyed on apex domain (5-min TTL)
    client_test.go
    cache_test.go
  detector.go          # Public API: Detector{}.Score(ctx, url) → Result
  detector_test.go
```

---

## Enrichment Pipeline — Exact Specification

Read `fusion_kit/enrich.py` and `fusion_kit/operational.py` to understand each step. Below is the precise contract your Go code must satisfy.

### DNS (`dns.go`)

- Input: hostname string
- Output: IP address string (IPv4 preferred), error
- Use `net.DefaultResolver`; respect context cancellation
- Cache results in-process for the lifetime of the binary (DNS results don't change meaningfully within a session)
- Timeout: 500ms

### WHOIS (`whois.go`)

- Input: domain (apex, e.g. `"example.com"`)
- Output: `WHOISResult{RegistrationDate, ExpiryDate, UpdatedDate, Registrar, NameServers string}`
- Use `github.com/likexian/whois` + `github.com/likexian/whois-parser`
- Parse the result to extract `creation_date` as an ISO 8601 string, `expiry_date`, `updated_date`, `registrar`, `name_servers` (comma-separated)
- Cache results in-process with 24h TTL (domain age is stable)
- Timeout: 5s
- On failure: return zero-value struct (all empty strings); do not propagate error — enrichment degrades gracefully

### GeoIP (`geoip.go`)

- Input: IP address string, path to MaxMind `.mmdb` files (passed at init time)
- The three `.mmdb` files live inside `fusion_export/fusion_kit/` — your Go service must be told where to find them (pass the directory as a config value)
- Use `github.com/oschwald/geoip2-golang`
- Output: `GeoIPResult{Country, CountryName, Region, City string, Latitude, Longitude float64, ASN int, ASNName, ISP string, CIDRBlock string}`
- **CDN ASN null-out**: if ASN is in the CDN set below, set Country/CountryName/Region/City/Latitude/Longitude to zero values (the "country" for CDN IPs is meaningless PoP location, not origin)
- CDN ASNs to null-out: `{13335, 209242, 20940, 16625, 54113, 16509, 14618, 15169, 36492, 8075, 8068, 32934, 63949, 19551, 22822, 60068}`
- `CIDRBlock`: read from ASN DB as the network prefix (e.g. `"93.184.216.0/24"`)
- On failure: return zero-value struct

### TLS (`tls.go`)

- Input: hostname, port (default 443)
- Use `crypto/tls` with `InsecureSkipVerify: true` (we want the cert data even for expired certs)
- Output: `TLSResult{Enabled bool, Issuer, Subject, ValidFrom, ValidTo string}`
- `ValidFrom` / `ValidTo`: ISO 8601 UTC strings (`time.Format(time.RFC3339)`)
- `Issuer`: CN of first cert in chain (e.g. `"Let's Encrypt Authority X3"`)
- `Subject`: CN of leaf cert
- Timeout: 2.5s
- On failure: `Enabled=false`, zero strings

### HTTP (`http.go`)

- Input: URL string
- Follow up to 10 redirects; record `FinalURL` after redirect chain
- Output: `HTTPResult{StatusCode int, FinalURL, Title, Language, FormActionDomain, FaviconURL string, PasswordFieldCount int, HasHiddenRedirect bool}`
- Use `net/http` with a 5s timeout and a browser-like User-Agent: `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"`
- Parse HTML for:
  - `<title>` → Title (strip tags, trim whitespace)
  - `<html lang="...">` → Language
  - `<form action="...">` → domain of first non-relative, non-fragment action URL → FormActionDomain
  - `<link rel="...icon" href="...">` or `<link href="..." rel="...icon">` → FaviconURL (first match)
  - `<input type="password">` → count → PasswordFieldCount
  - `<input type="hidden" name="redirect|return|return_to|next|goto|url|back|callback|destination">` → HasHiddenRedirect
- Read at most 512KB of body to avoid memory issues on large pages
- Language detection: use the `lang` HTML attribute; do not run external language detection
- On error: return zero-value struct with StatusCode=0

### URL Shortener (`shortener.go`)

- Load the shortener apex list from a Go file (`shorteners.go`) generated from `_SHORTENER_APEXES` in `enrich.py`
- Export the frozenset as a Go `map[string]struct{}` named `ShortenerApexes` with all 1,479 entries
- `IsShortener(url string) bool`: parse the URL, extract apex (last two labels), check membership
- `ResolveShortURL(ctx context.Context, url string) (string, error)`: 
  - Only attempt resolution if `IsShortener(url)` is true
  - Follow redirects with HEAD (fallback to GET if 405)
  - Return empty string if resolution fails or final URL has same apex
  - Timeout: 5s

**Generate `shorteners.go`** by reading `_SHORTENER_APEXES` from `enrich.py` and writing a Go file. Do this with a one-off Python/shell script during the PR — do not hand-type 1,479 entries.

### Feature Vector (`features.go`)

This is the most critical file. It maps all the enrichment outputs to the exact 44-column feature vector that `hgb_operational.joblib` expects. Read `operational.py` in full — every function there must have a Go equivalent.

```go
type FeatureVector struct {
    // Identity (not used by HGB but sent to sidecar for context)
    URL      string
    Hostname string
    Domain   string
    TLD      string

    // Network
    IPAddress string
    CIDRBlock string
    ASN       float64 // NaN if unknown; float64 because HGB expects float
    ASNName   string
    ISP       string

    // Geographic (zeroed for CDN ASNs)
    Country     string
    CountryName string
    Region      string
    City        string
    Latitude    float64 // NaN if unknown
    Longitude   float64 // NaN if unknown

    // TLS
    SSLEnabled    string // "true"/"false"/""
    CertIssuer    string
    CertSubject   string
    CertValidFrom string
    CertValidTo   string

    // HTTP
    HTTPStatusCode float64 // NaN if unknown
    PageTitle      string
    PageLanguage   string

    // WHOIS
    Registrar   string
    CreationDate string
    ExpiryDate  string
    UpdatedDate string
    NameServers string

    // Derived numeric features (NaN if inputs missing)
    DomainAgeDays        float64
    CertAgeDays          float64
    CertValiditySpanDays float64
    TitleBrandMismatch   float64
    TitleHasLoginKw      float64
    SubdomainDepth       float64
    SubdomainBrandCount  float64
    ApexIsNumeric        float64
    FormActionMismatch   float64
    IPInURL              float64
    NonStdPort           float64
    URLDomainCharRatio   float64
    FaviconDomainMismatch float64
    PasswordFieldCount   float64
    HasHiddenRedirect    float64
    IsEphemeralPlatform  float64
}
```

**Derived feature computation (port these from `operational.py` exactly):**

- `DomainAgeDays`: days since `CreationDate` (parsed ISO 8601 → now UTC). NaN if parse fails.
- `CertAgeDays`: days since `CertValidFrom`. NaN if parse fails.
- `CertValiditySpanDays`: days between `CertValidFrom` and `CertValidTo`. NaN if either fails.
- `TitleBrandMismatch`: 1.0 if page title contains a known brand name AND hostname does not end with any of that brand's canonical domains. 0.0 otherwise. Use the exact brand→domains map from `operational.py` (copy it verbatim into a Go `map[string][]string`).
- `TitleHasLoginKw`: 1.0 if page title (lowercased) contains any of: `login`, `log in`, `sign in`, `signin`, `sign-in`, `verify`, `verification`, `account`, `password`, `secure`, `security`, `authenticate`, `authentication`, `sicherheit`, `iniciar sesión`, `iniciar sesion`, `connexion`, `anmelden`, `mot de passe`, `identifiez`.
- `SubdomainDepth`: number of dot-separated labels in hostname minus 2 (apex). Floor at 0.
- `SubdomainBrandCount`: count of subdomain labels (and their hyphen/underscore parts) that appear in the subdomain keyword set from `operational.py` (`_SUBDOMAIN_BRAND_KEYWORDS`). Copy that set verbatim.
- `ApexIsNumeric`: 1.0 if the second-to-last label of hostname consists only of digits.
- `FormActionMismatch`: 1.0 if `FormActionDomain` is non-empty AND its apex domain ≠ hostname apex domain. Use Mozilla Public Suffix List for apex extraction (see below).
- `IPInURL`: 1.0 if hostname is a bare IPv4 or IPv6 address.
- `NonStdPort`: 1.0 if URL specifies a port other than 80 (http) or 443 (https).
- `URLDomainCharRatio`: fraction of non-alpha, non-dot characters in hostname (hyphens, digits, underscores). `non_alpha_count / len(hostname)`.
- `FaviconDomainMismatch`: 1.0 if FaviconURL is non-empty AND its apex domain ≠ hostname apex domain.
- `PasswordFieldCount`: integer cast to float64.
- `HasHiddenRedirect`: 1.0 if HasHiddenRedirect=true, else 0.0.
- `IsEphemeralPlatform`: 1.0 if hostname ends with any of the 22 suffixes from `_EPHEMERAL_PLATFORM_SUFFIXES` in `operational.py` (copy verbatim). 0.0 otherwise.

**Apex domain extraction (used in FormActionMismatch, FaviconDomainMismatch):**
Use `golang.org/x/net/publicsuffix` — `publicsuffix.EffectiveTLDPlusOne(hostname)`. This is equivalent to `tldextract` in Python. Fall back to last-two-labels if it errors.

**`FeatureVector.ToJSON() map[string]interface{}`**: serialize to the exact JSON structure the sidecar `/score-features` endpoint expects. NaN float64 values must serialize as JSON `null` (not `NaN`, which is invalid JSON). Use a custom marshaler that checks `math.IsNaN(v)` and substitutes `nil`.

---

## Enricher Orchestration (`enricher.go`)

```go
type EnrichedURL struct {
    OriginalURL  string
    ResolvedURL  string  // set if shortener resolved, else == OriginalURL
    IsShortener  bool
    Features     FeatureVector
}

type Enricher struct {
    GeoIPDir string  // path to directory containing the three .mmdb files
    // internal caches wired up at construction
}

func New(geoIPDir string) (*Enricher, error)

// Enrich runs all enrichment steps concurrently for one URL.
// Timeout for the whole operation: 8 seconds.
func (e *Enricher) Enrich(ctx context.Context, rawURL string) (EnrichedURL, error)
```

Inside `Enrich`:
1. If `IsShortener(rawURL)` → try `ResolveShortURL`; if it returns a different apex, use the resolved URL for enrichment; mark `IsShortener=true`
2. Parse URL → extract `hostname`, `domain` (apex), `tld`
3. Launch concurrently (use `errgroup` or equivalent):
   - DNS resolution
   - WHOIS (use apex domain)
   - TLS inspection (use hostname, port 443)
   - HTTP fetch (use original/resolved URL)
4. After DNS completes → launch GeoIP concurrently with remaining
5. Assemble `FeatureVector` from all results

---

## Sidecar Client (`client.go`)

```go
type Client struct {
    baseURL    string
    httpClient *http.Client
    cache      *Cache
}

func NewClient(baseURL string) *Client

type ScoreRequest struct {
    NormalizedURL string
    IsShortener   bool
    Features      FeatureVector
}

type ScoreResult struct {
    URL       string
    URLP      float64
    OpP       float64
    DeployP   float64
    Verdict   string  // "phishing" | "benign"
}

func (c *Client) Score(ctx context.Context, req ScoreRequest) (ScoreResult, error)
func (c *Client) ScoreBatch(ctx context.Context, reqs []ScoreRequest) ([]ScoreResult, error)
```

- POST to `/score-features`
- Timeout: 10s
- On sidecar error: return error (caller decides fail-open vs fail-closed)
- `ScoreBatch` sends all requests in one HTTP call (the endpoint accepts a list)

---

## LRU Cache (`cache.go`)

- Key: apex domain (e.g. `"example.com"`)
- Value: `ScoreResult`
- TTL: 5 minutes
- Max entries: 10,000
- Thread-safe
- Use `github.com/hashicorp/golang-lru/v2` or implement a simple TTL map with `sync.RWMutex`
- The `Detector` wraps the client with the cache — check cache before calling enricher/sidecar

---

## Public API (`detector.go`)

```go
type Config struct {
    SidecarURL string  // default "http://127.0.0.1:8765"
    GeoIPDir   string  // required: path to MaxMind .mmdb directory
    Threshold  float64 // default 0.35
}

type Result struct {
    URL         string
    EffectiveURL string
    URLP        float64
    OpP         float64
    DeployP     float64
    Verdict     string
    IsShortener bool
    CacheHit    bool
}

type Detector struct { ... }

func NewDetector(cfg Config) (*Detector, error)

// Score enriches the URL and calls the sidecar. Returns from cache if available.
// This is the only function the Go service handler needs to call.
func (d *Detector) Score(ctx context.Context, url string) (Result, error)
```

---

## Integration Into The Existing Service

Find where the Go service currently handles unknown URLs (feed miss). Insert the Layer 2 call there:

```go
// Pseudocode — find the real call site
feedResult, found := feedClient.Lookup(ctx, url)
if found {
    return feedResult  // Layer 1 handled it
}

// Layer 2: ML scoring for unknown URLs
mlResult, err := detector.Score(ctx, url)
if err != nil {
    log.Printf("phishing ML check failed for %s: %v", url, err)
    // Decide: fail-open (return benign) or fail-closed (return error)
    // Default: fail-open for Layer 2 (feed is the hard gate)
    return BenignResult(url)
}
return mlResult
```

Add `Detector` to whatever dependency injection / struct the service uses. Wire up `GeoIPDir` from config (environment variable or config file — follow the pattern already established in the codebase).

---

## Python Sidecar: How To Start It

The sidecar ships as part of `fusion_detector_v1.9.1.zip`. After unzipping, the Go service's README or Dockerfile should document:

```bash
pip install -r fusion_export/requirements.txt
python fusion_export/scripts/serve.py --port 8765 --threshold 0.35 --workers 4
```

For production: follow the Docker or systemd patterns in `fusion_export/GO_INTEGRATION.md`.

Update the sidecar's `serve.py` with the `/score-features` endpoint as described above — commit this modified `serve.py` in the same PR.

---

## Testing Requirements

Every module must have tests. Tests must pass before the PR is considered done. **Do not merge without green tests.**

### Unit Tests

**`dns_test.go`**: Test `ResolveIP` with a real hostname (`google.com`) and verify non-empty IP. Test with invalid hostname and verify empty string returned (not panic).

**`whois_test.go`**: Test `LookupWHOIS("google.com")` returns a non-empty RegistrationDate. Test with garbage input returns zero-value struct. (Use `t.Skip` if running without network — mark clearly.)

**`geoip_test.go`**: Test `LookupGeoIP("8.8.8.8", dir)` returns ASN=15169 (Google). Test CDN ASN null-out: `8.8.8.8` has CDN ASN → Country should be empty string. Test invalid IP returns zero-value struct.

**`tls_test.go`**: Test `GetTLSCert("google.com", 443)` returns `Enabled=true` and non-empty Issuer. Test against expired-cert host or bad hostname returns `Enabled=false`.

**`http_test.go`**: Use `httptest.NewServer` to serve synthetic HTML:
```html
<html lang="en">
<head><title>PayPal Login</title>
<link rel="icon" href="https://paypal.com/favicon.ico">
</head>
<body>
<form action="https://evil.com/steal">
<input type="password" name="pass">
<input type="hidden" name="redirect" value="/">
</form>
</body>
</html>
```
Assert: Title=`"PayPal Login"`, Language=`"en"`, FormActionDomain=`"evil.com"`, FaviconURL contains `"paypal.com"`, PasswordFieldCount=1, HasHiddenRedirect=true, StatusCode=200.

**`features_test.go`**: Build a `FeatureVector` with known inputs and assert:
- `TitleBrandMismatch=1.0` when title contains `"paypal"` and hostname is `"evil.com"`
- `TitleBrandMismatch=0.0` when title contains `"paypal"` and hostname is `"paypal.com"`
- `TitleHasLoginKw=1.0` when title contains `"login"`
- `IsEphemeralPlatform=1.0` for `"anything.vercel.app"`
- `IsEphemeralPlatform=0.0` for `"anything.example.com"`
- `SubdomainDepth=2.0` for `"a.b.example.com"`
- `SubdomainBrandCount=1.0` for `"paypal.evil.com"` (paypal is a brand keyword)
- `IPInURL=1.0` for `"http://192.168.1.1/path"`
- `NonStdPort=1.0` for `"https://example.com:8443/path"`
- `URLDomainCharRatio` is correct for `"a1-b.example.com"` (2 non-alpha-non-dot out of 14)
- `DomainAgeDays` is approximately correct for a fixed creation_date
- `ToJSON()` serializes NaN float64 as `null`, not `NaN`

**`shortener_test.go`**:
- `IsShortener("https://bit.ly/abc123")` returns true
- `IsShortener("https://google.com/")` returns false
- `ShortenerApexes` has length 1479
- `ResolveShortURL` with a mock HTTP server that redirects to a different apex returns the final URL

**`cache_test.go`**:
- Set a value, get it back immediately → hit
- Set a value with 1ms TTL, sleep 2ms, get → miss
- Concurrent reads/writes do not race (use `-race` flag)

**`client_test.go`**:
- Use `httptest.NewServer` to mock the sidecar's `/score-features` endpoint
- Verify correct JSON serialization of request
- Verify correct deserialization of response
- Verify cache is checked before making HTTP call on second identical request

### Integration Test

**`detector_test.go`**: Start a real sidecar subprocess using `exec.Command` pointing at the actual `fusion_export/scripts/serve.py`. This test is guarded by `//go:build integration` and requires `GEOIP_DIR` env var and Python in PATH.

```go
//go:build integration

func TestDetector_LivePhishingURL(t *testing.T) {
    // Start sidecar
    // Score a known phishing URL from fusion_export/live_phishing_urls.txt
    // Assert Verdict == "phishing"
}

func TestDetector_LiveBenignURL(t *testing.T) {
    // Score google.com
    // Assert Verdict == "benign"
}
```

### Sidecar Test

Write a Python test for the new `/score-features` endpoint:

```python
# fusion_export/tests/test_score_features.py
import pytest, requests, subprocess, time, json

@pytest.fixture(scope="module")
def sidecar():
    proc = subprocess.Popen(["python", "scripts/serve.py", "--port", "8766"])
    time.sleep(3)
    yield "http://127.0.0.1:8766"
    proc.terminate()

def test_score_features_benign(sidecar):
    payload = {"requests": [{"normalized_url": "https://google.com/", "is_shortener": False, "features": {
        "url": "https://google.com/", "hostname": "google.com", "domain": "google.com",
        "tld": "com", "http_status_code": 200, "domain_age_days": 10000.0,
        "cert_age_days": 30.0, "cert_validity_span_days": 90.0,
        "title_brand_mismatch": 0.0, "title_has_login_kw": 0.0,
        "subdomain_depth": 0.0, "subdomain_brand_count": 0.0, "apex_is_numeric": 0.0,
        "form_action_mismatch": 0.0, "ip_in_url": 0.0, "non_std_port": 0.0,
        "url_domain_char_ratio": 0.0, "favicon_domain_mismatch": 0.0,
        "password_field_count": 0.0, "has_hidden_redirect": 0.0, "is_ephemeral_platform": 0.0
    }}]}
    r = requests.post(f"{sidecar}/score-features", json=payload)
    assert r.status_code == 200
    result = r.json()["results"][0]
    assert result["verdict"] == "benign"
    assert result["deploy_p"] < 0.35

def test_score_features_phishing(sidecar):
    # Use a high-signal feature vector that should score > 0.35
    payload = {"requests": [{"normalized_url": "https://paypal-secure-login.vercel.app/verify", "is_shortener": False, "features": {
        "url": "https://paypal-secure-login.vercel.app/verify", "hostname": "paypal-secure-login.vercel.app",
        "domain": "vercel.app", "tld": "app", "http_status_code": 200,
        "domain_age_days": 2.0, "cert_age_days": 1.0, "cert_validity_span_days": 90.0,
        "title_brand_mismatch": 1.0, "title_has_login_kw": 1.0,
        "subdomain_depth": 1.0, "subdomain_brand_count": 1.0, "apex_is_numeric": 0.0,
        "form_action_mismatch": 0.0, "ip_in_url": 0.0, "non_std_port": 0.0,
        "url_domain_char_ratio": 0.2, "favicon_domain_mismatch": 1.0,
        "password_field_count": 2.0, "has_hidden_redirect": 1.0, "is_ephemeral_platform": 1.0
    }}]}
    r = requests.post(f"{sidecar}/score-features", json=payload)
    assert r.status_code == 200
    result = r.json()["results"][0]
    assert result["op_p"] > 0.5  # HGB should score this high

def test_score_features_shortener(sidecar):
    # Shortener mask should shift weight to op_p
    payload = {"requests": [{"normalized_url": "https://bit.ly/abc123", "is_shortener": True, "features": {
        "url": "https://bit.ly/abc123", "hostname": "bit.ly", "domain": "bit.ly",
        "tld": "ly", "http_status_code": 301, "domain_age_days": 5000.0,
        "cert_age_days": 30.0, "cert_validity_span_days": 365.0,
        "title_brand_mismatch": 0.0, "title_has_login_kw": 0.0,
        "subdomain_depth": 0.0, "subdomain_brand_count": 0.0, "apex_is_numeric": 0.0,
        "form_action_mismatch": 0.0, "ip_in_url": 0.0, "non_std_port": 0.0,
        "url_domain_char_ratio": 0.0, "favicon_domain_mismatch": 0.0,
        "password_field_count": 0.0, "has_hidden_redirect": 0.0, "is_ephemeral_platform": 0.0
    }}]}
    r = requests.post(f"{sidecar}/score-features", json=payload)
    assert r.status_code == 200
    result = r.json()["results"][0]
    assert result["verdict"] == "benign"  # trusted domain profile, shortener mask applied
```

---

## Dependencies To Add

**Go `go.mod`**:
```
github.com/likexian/whois v1.15.6 (or latest)
github.com/likexian/whois-parser v1.24.20 (or latest)
github.com/oschwald/geoip2-golang v1.11.0 (or latest)
github.com/hashicorp/golang-lru/v2 v2.0.7 (or latest)
golang.org/x/net (for publicsuffix)
```

**Python `requirements.txt`** in the zip: no changes needed (all dependencies already present).

---

## What NOT To Do

- Do not use CGO to call Python from Go
- Do not ship the `.mmdb` files in git — document that they come from the zip
- Do not re-implement the ML models in Go — the Python sidecar handles inference
- Do not change the existing `/score` endpoint in `serve.py` — backward compatible
- Do not change the fusion threshold (0.35) — it is validated against benchmark
- Do not add the `/score-features` endpoint to the old `_lock`-serialized path — it can be concurrent since it does no I/O
- Do not hand-type the shortener list — generate `shorteners.go` programmatically

---

## Model Performance Context (For PR Description)

The model being integrated was evaluated on:
- **Benchmark** (synthetic): TP=450 FN=30 TN=210 FP=0 across seeds 42, 1337, 2025
- **PhishTank live (5,003 URLs) vs Tranco benign (800 URLs)**: ROC-AUC=0.9946, TPR=97.5%, FPR=5.1%
- Threshold: 0.35

Known limitations (document in PR description):
1. OAuth redirect injection (`?redirect_uri=evil`) — surface URL is legit host
2. Platform phishing without brand name in URL/title — requires content gate
3. Compromised legitimate sites — domain looks clean operationally

---

## Deliverables For The PR

1. `fusion_export/scripts/serve.py` — modified with `/score-features` endpoint
2. `fusion_export/tests/test_score_features.py` — Python tests
3. `internal/phishing/**/*.go` — complete Go enricher + client + detector
4. Updated `go.mod` / `go.sum`
5. Config wiring (GeoIPDir, SidecarURL from env/config)
6. Documentation in service README: how to start the sidecar, where to put `.mmdb` files
7. PR description with architecture diagram, performance numbers, known limitations

**All Go tests must pass with `go test ./internal/phishing/...`. All Python tests must pass with `pytest fusion_export/tests/`. The integration test must be gated with `//go:build integration`.**
