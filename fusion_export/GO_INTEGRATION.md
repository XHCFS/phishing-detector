# Integrating the Fusion Phishing Detector into a Go Service

The Python model runs as a **sidecar HTTP process** alongside your Go binary. Go calls it over loopback HTTP — no CGO, no Python bindings, no shared memory. The sidecar handles enrichment (WHOIS, GeoIP, TLS, HTTP fetch) and scoring; Go handles everything else (routing, auth, caching, rate limiting, alerting).

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│  Your Go service                                        │
│                                                         │
│  handler.go ──► phishing.Client.Score(urls) ──────────┐│
│                                                         ││
│  Response:  verdict="phishing"|"benign"                 ││
│             deploy_p=0.87  url_p=0.91  op_p=0.83       ││
└────────────────────────────────────────────────────────┘│
                                                          │
                    HTTP POST /score                       │
                    (loopback, 127.0.0.1:8765)            │
                                                          ▼
┌─────────────────────────────────────────────────────────┐
│  fusion sidecar  (scripts/serve.py)                     │
│                                                         │
│  • URL char n-gram LR    (url_char_lr.joblib)           │
│  • Operational HGB       (hgb_operational.joblib)       │
│  • Live enrichment       (WHOIS / GeoIP / TLS / HTTP)   │
│  • Optional content gate (HTML analysis)                │
└─────────────────────────────────────────────────────────┘
```

---

## 1. Deploy the sidecar

Copy the `fusion_export/` directory into your repo (anywhere — it is self-contained):

```
your-go-repo/
  cmd/
  internal/
  phishing/          ← drop fusion_export/ here, rename if you like
    fusion_kit/
    models/
    scripts/
    requirements.txt
    GO_INTEGRATION.md
```

Install Python dependencies (Python ≥ 3.11):

```bash
cd phishing/
pip install -r requirements.txt
```

Start the sidecar (in production: run as a systemd unit or Docker sidecar — see §5):

```bash
python scripts/serve.py \
  --port 8765 \
  --threshold 0.35 \
  --workers 6
```

Liveness probe:

```bash
curl http://127.0.0.1:8765/health
# {"status":"ok","models_loaded":true}
```

---

## 2. Go client

Drop this file into your Go service (adjust the package and import path):

```go
// internal/phishing/client.go
package phishing

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

const defaultSidecarURL = "http://127.0.0.1:8765"

type Verdict string

const (
    VerdictPhishing Verdict = "phishing"
    VerdictBenign   Verdict = "benign"
)

type Result struct {
    URL         string  `json:"url"`
    EffectiveURL string `json:"effective_url"`
    URLScore    float64 `json:"url_p"`
    OpScore     float64 `json:"op_p"`
    DeployScore float64 `json:"deploy_p"`
    Verdict     Verdict `json:"verdict"`

    // Only set when sidecar is started with --content-gate
    CGTriggered bool     `json:"cg_triggered"`
    CGScore     float64  `json:"cg_score"`
    CGSignals   []string `json:"cg_signals"`
}

type scoreRequest struct {
    URLs []string `json:"urls"`
}

type scoreResponse struct {
    Results     []Result `json:"results"`
    Threshold   float64  `json:"threshold"`
    FusionMode  string   `json:"fusion_mode"`
}

// Client calls the fusion sidecar.
type Client struct {
    http    *http.Client
    baseURL string
}

// NewClient returns a Client pointed at the sidecar.
// baseURL defaults to http://127.0.0.1:8765 if empty.
func NewClient(baseURL string) *Client {
    if baseURL == "" {
        baseURL = defaultSidecarURL
    }
    return &Client{
        baseURL: baseURL,
        http: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// Score sends up to 500 URLs to the sidecar and returns one Result per URL.
// Order is preserved.
func (c *Client) Score(ctx context.Context, urls []string) ([]Result, error) {
    if len(urls) == 0 {
        return nil, nil
    }

    body, err := json.Marshal(scoreRequest{URLs: urls})
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        c.baseURL+"/score", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.http.Do(req)
    if err != nil {
        return nil, fmt.Errorf("phishing sidecar unreachable: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("phishing sidecar returned %d", resp.StatusCode)
    }

    var out scoreResponse
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, err
    }
    return out.Results, nil
}

// ScoreOne is a convenience wrapper for scoring a single URL.
func (c *Client) ScoreOne(ctx context.Context, url string) (Result, error) {
    results, err := c.Score(ctx, []string{url})
    if err != nil || len(results) == 0 {
        return Result{}, err
    }
    return results[0], nil
}

// IsPhishing returns true if the URL scores above the model threshold.
// This is the single-line integration point for existing handler code.
func (c *Client) IsPhishing(ctx context.Context, url string) (bool, error) {
    r, err := c.ScoreOne(ctx, url)
    if err != nil {
        return false, err
    }
    return r.Verdict == VerdictPhishing, nil
}
```

---

## 3. Usage in a handler

```go
// cmd/server/main.go  (abbreviated)
package main

import (
    "context"
    "log"
    "net/http"

    "yourmodule/internal/phishing"
)

func main() {
    phishClient := phishing.NewClient("") // defaults to 127.0.0.1:8765

    http.HandleFunc("/submit-url", func(w http.ResponseWriter, r *http.Request) {
        url := r.FormValue("url")

        result, err := phishClient.ScoreOne(r.Context(), url)
        if err != nil {
            // Sidecar down — fail open or closed depending on your policy
            log.Printf("phishing check failed for %s: %v", url, err)
            http.Error(w, "scoring unavailable", http.StatusServiceUnavailable)
            return
        }

        if result.Verdict == phishing.VerdictPhishing {
            log.Printf("BLOCKED phishing URL: %s deploy_p=%.3f", url, result.DeployScore)
            http.Error(w, "URL blocked: phishing detected", http.StatusForbidden)
            return
        }

        // proceed with benign URL
        w.WriteHeader(http.StatusOK)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Batch scoring (e.g. scanning a feed of URLs)

```go
urls := []string{
    "https://example1.com",
    "https://example2.com/login",
    // up to 500 per call
}

results, err := phishClient.Score(ctx, urls)
if err != nil {
    log.Fatal(err)
}

for _, r := range results {
    if r.Verdict == phishing.VerdictPhishing {
        log.Printf("phishing: %s (deploy_p=%.4f, url_p=%.4f, op_p=%.4f)",
            r.URL, r.DeployScore, r.URLScore, r.OpScore)
    }
}
```

---

## 4. Configuration reference

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8765` | TCP port the sidecar listens on |
| `--host` | `127.0.0.1` | Bind address (use `0.0.0.0` only if Go and Python are on separate hosts, protected by a firewall) |
| `--threshold` | `0.35` | Fusion score above which verdict = `"phishing"`. **Must match any hardcoded threshold in your Go client if you add one.** |
| `--workers` | `6` | Concurrent enrichment threads per request |
| `--content-gate` | off | Enable second-pass HTML analysis for gray-zone URLs (slower, higher recall) |
| `--fusion` | `mean` | `mean` or `max` of url_p and op_p |
| `--models-dir` | `./models` | Override path to `.joblib` files |

---

## 5. Production deployment

### systemd unit (Linux)

```ini
# /etc/systemd/system/phishing-sidecar.service
[Unit]
Description=Phishing detection sidecar
After=network.target
PartOf=your-go-service.service

[Service]
Type=simple
User=appuser
WorkingDirectory=/opt/your-app/phishing
ExecStart=/usr/bin/python3 scripts/serve.py \
    --port 8765 \
    --threshold 0.35 \
    --workers 6
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker sidecar

```dockerfile
# Dockerfile.sidecar
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8765
CMD ["python", "scripts/serve.py", "--host", "0.0.0.0", "--port", "8765", \
     "--threshold", "0.35", "--workers", "6"]
```

```yaml
# docker-compose.yml (excerpt)
services:
  app:
    build: .
    environment:
      PHISHING_SIDECAR_URL: http://phishing-sidecar:8765
    depends_on:
      phishing-sidecar:
        condition: service_healthy

  phishing-sidecar:
    build:
      context: ./phishing
      dockerfile: Dockerfile.sidecar
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8765/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

---

## 6. Operational notes

**Latency**: A single-URL `/score_one` call takes 1–8 seconds — almost entirely enrichment (WHOIS, HTTP fetch, GeoIP). For user-facing flows, score asynchronously and return a preliminary result, or use a short-circuit cache keyed on apex domain.

**Caching**: The sidecar has no built-in cache. Add an in-process LRU cache in the Go client keyed on `effective_url` (not the original URL — shorteners resolve before scoring). A 5-minute TTL is appropriate; phishing infrastructure turns over in hours, not seconds.

```go
// Sketch: wrap ScoreOne with a simple TTL cache
type cachedClient struct {
    inner *phishing.Client
    cache *ttlcache.Cache[string, phishing.Result]
}

func (c *cachedClient) ScoreOne(ctx context.Context, url string) (phishing.Result, error) {
    if r, ok := c.cache.Get(url); ok {
        return r, nil
    }
    result, err := c.inner.ScoreOne(ctx, url)
    if err == nil {
        c.cache.Set(url, result, 5*time.Minute)
    }
    return result, err
}
```

**Fail-open vs fail-closed**: If the sidecar is unreachable, the Go client returns an error. Decide your policy at the call site:
- Fail-open (`return nil` — let the URL through): appropriate when phishing detection is advisory and UX matters
- Fail-closed (`return error` — block the request): appropriate when this is a hard security gate

**Model updates**: Replace `models/url_char_lr.joblib` and `models/hgb_operational.joblib`, then restart the sidecar. No Go redeployment needed. Verify checksums before swapping (see `scripts/checksum_models.py`).

---

## 7. Known limitations

- **JavaScript-rendered pages**: enrichment fetches raw HTML; pages behind JS challenges (Cloudflare, bot detection) may return challenge pages, not real content. Content gate signals are less reliable for these.
- **Open redirects on non-shortener hosts**: the sidecar follows HTTP 301/302 chains and scores the final destination; it does not execute meta-refresh or JS-based redirects.
- **Throughput**: the sidecar is single-threaded HTTP (stdlib `HTTPServer`). For >10 concurrent Go goroutines hitting it, add a connection pool or replace with `gunicorn -w 4 -k gthread`. A mutex (`_lock`) currently serializes scoring — remove it if you switch to a multi-worker WSGI server.
- **Threshold is fixed at startup**: changing it requires a sidecar restart. If you need per-request thresholds, pass a `threshold` field in the JSON body and modify `serve.py` to read it (one-line change in `Handler.do_POST`).
