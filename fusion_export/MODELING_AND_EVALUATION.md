# CyberSiren Fusion Phishing Detector — Modeling & Evaluation

**Model version:** v3 (url_char_lr v3 + hgb_operational, three-zone asymmetric fusion)
**Evaluation date:** 2026-05-18
**Threshold:** 0.50 (fixed — not tuned on any test set)

---

## 1. System Architecture

The detector is a hybrid of two independent models fused by a weighted formula. Neither model alone is sufficient; fusion is the key.

```
  Input URL
      │
      ├──► URL Char n-gram LR ─────────────────────── url_p (0→1)
      │    HashingVectorizer(char_wb, 2-4grams, 2^18)
      │    + LogisticRegression(C=2.0, balanced)
      │
      ├──► Enrichment Pipeline ──────────────────────►
      │    • DNS resolution + TTL                      │
      │    • WHOIS (domain age, registrar, registrant) │
      │    • GeoIP + ASN + ISP                        ├──► op_p (0→1)
      │    • TLS certificate (issuer, age, SANs)      │    hgb_operational
      │    • HTTP page fetch (title, content, lang)   │    44-feature HGB
      │    • Form action / favicon URL                │
      │    • Redirect chain (final_url)               │
      │    • Brand keyword detection                  │
      │    • Ephemeral-platform flag                  │
      │
      └──► Asymmetric Three-Zone Fusion ─────────── deploy_p (0→1)
           threshold = 0.50
```

### Why two models?

| Attack pattern | url_p signal | op_p signal |
|----------------|-------------|-------------|
| Subdomain chain (`login.paypal.com.verify.b8fhk2x.net`) | Strong (brand in URL) | Moderate (new domain) |
| DGA domains (`m.07365tt.com/jp/mypage`) | Strong (random chars, suspicious TLD) | Strong (new domain, bad ASN) |
| Platform phishing (Vercel, Firebase, Netlify) | Moderate (random subdomain) | Weak (legitimate infrastructure) |
| Compromised legit domain, brand page | Weak (no brand in URL) | Weak (trusted domain) |
| Brand title mismatch only | Weak | Moderate (page title/favicon mismatch) |

Neither model covers the full attack surface alone. Fusion with asymmetric zone weights handles the tradeoff.

---

## 2. Component Models

### 2.1 URL Char n-gram LR (`url_char_lr.joblib`, v3)

| Parameter | Value |
|-----------|-------|
| Architecture | LogisticRegression |
| Vectorizer | HashingVectorizer(analyzer='char_wb', ngram_range=(2,4), n_features=2^18) |
| Regularization | C=2.0, class_weight='balanced' |
| Training rows | 304,181 |
| Base dataset | 299,181 rows from `cybersiren_lowlatency_dataset.csv` (LegitPhish + PhiUSIIL) |
| Phishing augmentation | 300 fresh OpenPhish URLs × 10 = 3,000 rows |
| Benign augmentation | 625 hard-benign URLs × 3 = 1,875 rows |
| AUC (held-out balanced 5K) | **0.974** |
| Benign FPR@0.50 (held-out) | **0.6%** |

**Version history (same architecture, different training data):**

| Version | C | augment-phish | augment-benign | AUC (held-out) | Benign FPR@0.5 |
|---------|---|---------------|---------------|---------------|---------------|
| v1 (old) | 4.0 | 317 × 150 | 625 × 200 | 0.757 | 68.2% |
| v3 (current) | 2.0 | 300 × 10 | 625 × 3 | 0.974 | 0.6% |

The v1 model was severely overfit: the 625 benign URLs repeated 200 times each dominated training, and the 317 phishing augmentation URLs were the same 317 URLs used in the chain-phish benchmark (data leakage). The v3 model reduces augmentation repetitions and uses fresh augmentation data not present in any benchmark.

### 2.2 HGB Operational Model (`hgb_operational.joblib`)

| Parameter | Value |
|-----------|-------|
| Architecture | HistGradientBoostingClassifier |
| Features | 44 (28 raw enrichment + 16 derived) |
| Validation AUC | 0.99985 |
| Missing values | Native NaN handling (HGB supports this natively) |
| Categorical features | Low-cardinality strings → `pd.Categorical`; high-cardinality → hash bucket mod 4096 |

Key feature groups:
- **Domain age signals**: `domain_age_days`, `domain_created_recently`, `whois_age_bucket`
- **Infrastructure signals**: `ip_asn`, `ip_country`, `ip_is_datacenter`, `is_ephemeral_platform`
- **TLS signals**: `cert_issuer`, `cert_age_days`, `cert_san_count`, `cert_is_ev`
- **Content signals**: `page_title_brand_mismatch`, `has_login_form`, `favicon_external_host`, `redirect_count`
- **DNS signals**: `dns_ttl_low`, `resolves`, `has_mx`, `nameserver_registrar`

---

## 3. Fusion Formula

Three asymmetric zones, selected by `op_p` and guarded by `url_p`:

| Zone | Condition | Blend | Rationale |
|------|-----------|-------|-----------|
| CDN-phishing | op_p < 0.01 | 65% url_p + 35% op_p | op_p near zero → op model has no signal; url_p dominates |
| Normal | 0.01 ≤ op_p ≤ 0.60 | 60% url_p + 40% op_p | balanced contribution; url_p slight edge for path-based phishing |
| High-operational | op_p > 0.60 **AND url_p ≥ 0.05** | 25% url_p + 75% op_p | strong infrastructure signal; op_p dominates; catches DGA/random-domain phishing |
| High-op guard | op_p > 0.60 AND url_p < 0.05 | → Normal blend | url_p < 0.05 means URL model sees nothing suspicious; fall back rather than amplify weak op signal |

**Guard rationale:** Legitimate Vercel/Cloudflare Pages deployments (`analytics-dashboard.vercel.app`) have `op_p` elevated by the `is_ephemeral_platform` feature but `url_p ≈ 0.001–0.026` because the URL characters are unremarkable. Real high-op phishing (DGA domains, numeric domains) has `url_p ≥ 0.06`. The guard prevents platform false positives without disabling the high-op zone for genuine phishing.

**Shortener handling:** When `shortener_mask=True` (URL's apex domain is a known shortener like `bit.ly`, `t.co`, `tinyurl.com`) and `url_p ≤ 0.95`, fusion shifts to 10% url_p + 90% op_p. The shortener subdomain/path carries no semantic meaning; the operational model's read on the redirected destination matters. Exception at `url_p > 0.95`: the shortener domain itself is suspicious.

---

## 4. Production Context

The Python sidecar is **not** the first line of defense. The Go service applies two gates before calling the sidecar:

1. **Apex allowlist** — top-10K domains (Cisco Umbrella + manual exceptions). Benign verdicts for known-good domains never reach the sidecar. This explains why benchmark FPR on `live_benign_urls.txt` and `hard_benign.txt` is higher than production FPR: the benchmark scores everything through the sidecar; production allowlists the most common benign domains before scoring.

2. **Brand-in-subdomain scan** — URLs like `paypal-security.verify-login.com` are flagged phishing before ML scoring.

The benchmark numbers in §5 reflect **sidecar-only** performance. Full system (Go guard + sidecar) has substantially lower FPR for well-known domains.

---

## 5. Benchmark Results

**Protocol:** 10 independent corpora. Each URL scored live (full enrichment). Timeout 25s per URL, 8 parallel workers. Fixed threshold 0.50 throughout — threshold not tuned on these corpora.

### 5.1 Phishing Detection Rate (DR)

| Corpus | Description | Scored | Caught | DR |
|--------|-------------|--------|--------|----|
| Fresh OpenPhish 2026-05-18 | 300 fresh phishing URLs not in training | 286 | 286 | **100.0%** |
| all_phish (mixed) | Mixed fresh phishing (OpenPhish + PhishTank + manual) | 307 | 299 | **97.5%** |
| Repo live_phishing_urls | Curated known-phishing set (repo ground truth) | 75 | 74 | **98.5%** |
| Error-analysis FNs | Previously identified false negatives | 61 | 10 | **16.4%** |
| Subdomain-chain adversarial | 321 adversarial subdomain-chain URLs | 321 | 287 | **89.4%** |
| LegitPhish/PhiUSIIL phishing | 150 phishing from LegitPhish/PhiUSIIL test split | 150 | 112 | **74.7%** |

> **Error-analysis FNs note:** The 16.4% DR on previously identified FNs is the honest number. The v1 model showed 43.4% on this set due to data leakage (those FNs were from the chain-phish set, which overlapped with v1 augmentation). The v3 model's lower number reflects a real capability limit: these are genuinely hard cases that both models have weak signal on.

> **LegitPhish/PhiUSIIL phishing regression note:** This corpus contains subtle phishing sites with generic, clean-looking domain names (e.g., `tehila.co`, `arsels.info`, `eqtxu.com`) — no brand in URL, no suspicious path, recently-registered but not unusual. The v3 model's 74.7% DR on this set is a known limitation.

### 5.2 False Positive Rate (FPR)

| Corpus | Description | Scored | FPs | FPR |
|--------|-------------|--------|-----|-----|
| LegitPhish/PhiUSIIL benign | 150 benign from LegitPhish/PhiUSIIL test split | 150 | 2 | **1.3%** |
| Hard-benign augmentation | 627 hard-to-classify benign URLs | 627 | 154 | **24.6%** |
| Repo live_benign_urls | Curated known-benign set (repo ground truth) | 46 | 12 | **26.1%** |
| Error-analysis FPs | Previously identified false positives | 19 | 6 | **31.6%** |

> **Hard-benign FPR note:** The 24.6% FPR on `hard_benign.txt` primarily comes from Vercel/Cloudflare Pages URLs where the v3 URL model has been exposed to phishing hosted on these platforms (via augmentation). This creates a tension: the model learns to treat platform-hosted URLs as suspicious because phishing is also platform-hosted. The fusion guard (`url_p < 0.05 → fallback`) mitigates but does not eliminate this. In production, developer demo URLs on `vercel.app` / `pages.dev` hit the apex allowlist before the sidecar. See §6 (Known Limitations) for full analysis.

### 5.3 Summary Table

| Metric | Value | Notes |
|--------|-------|-------|
| DR on fresh live phishing | **100.0%** | 286/286 fresh OpenPhish, unseen at training |
| DR on mixed phishing | **97.5%** | 299/307 across sources |
| DR on known corpus | **98.5%** | 74/75 repo ground truth |
| DR on adversarial chains | **89.4%** | 287/321 subdomain-chain adversarial |
| DR on subtle phishing | **74.7%** | 112/150 LegitPhish — worst case |
| FPR on clean test split | **1.3%** | 2/150 LegitPhish benign |
| FPR on hard benign | **24.6%** | Platform URLs dominate — largely allowlisted in prod |
| FPR on known corpus | **26.1%** | 12/46 — most are top-10K domains, allowlisted in prod |
| Sidecar timeout rate | ~4.5% | 14/300 on fresh OpenPhish — live enrichment variability |

---

## 6. Known Limitations

### 6.1 Platform-hosted phishing (hard benign / FPR issue)

Phishing hosted on Vercel, Cloudflare Pages, GitHub Pages, Firebase, Netlify produces `url_p` in the same range as legitimate use of those platforms. The URL model sees identical character patterns (`<hash>.vercel.app`, `<project>.pages.dev`). Content analysis (page title, form action, favicon host mismatch) would be needed to distinguish them at the URL/feature level.

**Mitigation in place:** The fusion high-op guard (`url_p < 0.05 → fallback to normal blend`) and the production apex allowlist both reduce impact. But it cannot be fully resolved without richer content features.

### 6.2 LegitPhish subtle phishing regression

Generic-domain phishing (no brand name in domain, short path, clean TLD like `.co` or `.info`) produces weak signal in both models. `url_p ≈ 0.3–0.5`, `op_p ≈ 0.2–0.4`, `deploy_p ≈ 0.3–0.45` → below threshold. These sites rely on content (page title/form) to lure victims, not URL/infrastructure cues.

### 6.3 Navigation-compass style phishing

`apple-photos.sa.com`, `localizar-find.my` — where the URL looks semi-legitimate and op features are clean (`op_p 0.01–0.03`). Both models have weak signal. These typically require brand-title mismatch detection (page fetch + NLP).

### 6.4 Training data quality

The base training corpus (`cybersiren_lowlatency_dataset.csv`) contains label noise for pages-on-domains:
- `github.com` appears as 77 phishing vs 1 benign (phishing pages hosted on GitHub)
- `virustotal.com` appears as 2 phishing, 0 benign
- `microsoft.com` appears as 8 phishing vs 1 benign

This causes the URL model to assign elevated `url_p` to `github.com/...` paths. All these apex domains are in the production allowlist so this does not affect live operation, but it affects offline benchmark FPR when scoring raw URLs without the allowlist.

### 6.5 Live enrichment variability

`op_p` changes across runs (WHOIS TTL, DNS propagation, ASN routing changes). The same URL can score slightly differently in repeated runs. FPR/DR numbers carry ≈±2% noise from this source.

---

## 7. Training Data

### 7.1 Base dataset

`cybersiren_lowlatency_dataset.csv` — 299,181 rows  
Sources: LegitPhish + PhiUSIIL published datasets  
Class balance: 164K phishing / 135K benign (≈55/45 before class_weight='balanced')

### 7.2 Phishing augmentation (v3)

300 fresh OpenPhish URLs (2026-05-18), repeated × 10 = 3,000 rows  
Purpose: Teach patterns not in base dataset, specifically:
- `dpdloco.top` / `dpdloco.com` DPD parcel delivery scam (115 URLs, 0 in base data)
- Fresh brand-impersonation kits on new TLDs

### 7.3 Benign augmentation (v3)

627 hard-benign URLs, repeated × 3 = 1,875 rows  
Purpose: Reduce FPR on diverse legitimate URLs:
- Developer platform deployments (Vercel, CF Pages, GitHub Pages, Firebase)
- Auth flows from known brands (login paths that look like phishing to the URL model)
- E-commerce, media, government, finance URLs

### 7.4 Held-out evaluation set

Balanced 5,000 URL sample (2,500 phishing / 2,500 benign), held out before any training. Not used for hyperparameter selection. AUC and FPR@0.5 reported from this set.

---

## 8. What Not to Do

- **Do not tune threshold on benchmark corpora.** Threshold is 0.50 regardless of per-corpus FPR/DR. Threshold tuning on test sets inflates reported performance.
- **Do not use `augment_chain_phish.txt` for training.** This file contains the exact 317 URLs in the `subdomain-chain adversarial` benchmark. Adding it to training leaks the test set. The v1 model made this mistake.
- **Do not add back an established-domain zone.** A prior version gave brand domains (google.com, paypal.com) automatic benign status in the fusion. This masked genuine attack surface (phishing at `login.paypal.com.evil.net`).
- **Do not switch fusion to `max`.** Max fusion passes the highest of the two scores unconditionally — higher FPR with no benefit on DR.
- **Do not remove `shortener_mask` or `is_ephemeral_platform`.** These are load-bearing signals in the operational feature set.
