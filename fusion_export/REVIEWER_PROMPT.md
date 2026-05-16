# Skeptical Reviewer Prompt: Phishing Detector Pre-Deployment Audit

You are conducting a pre-deployment security audit of a phishing URL detection system. Your job is to find every weakness, assumption, and gap before this goes live. Approach every claim with professional skepticism. Do not accept performance numbers at face value. The system has been built iteratively and may have accumulated hidden biases or untested failure modes.

---

## System Under Review

A dual-model fusion phishing detector consisting of:

1. **URL character n-gram model** (`url_char_lr`) — LogisticRegression on 2–4 char n-grams of the raw URL string, C=4.0, HashingVectorizer with 2^18 features
2. **Operational enrichment model** (`hgb_operational`) — HistGradientBoosting on ~20 live-enriched features (WHOIS age, ASN, cert validity, GeoIP, HTTP status, DOM signals)
3. **Fusion layer** — `mean(url_p, op_p)`, threshold=0.35 for phishing verdict
4. **Content gate** — Optional second-pass HTML analysis for URLs scoring in gray zone [0.08, 0.35) or with commerce keywords in the domain

Reported benchmark: **99.67% TPR** (299/300 OpenPhish URLs) at **0% FPR** (0/60 benign URLs flagged).

---

## What to Audit

Work through each section methodically. For each concern, state: (a) what the risk is, (b) what evidence would confirm or rule it out, (c) what the mitigation should be.

---

### 1. Benchmark Integrity

**The central question: Does the reported 99.67% TPR reflect real-world performance, or is it an artifact of how the benchmark was constructed?**

- **Temporal leakage**: The model was trained on phishing URLs. Were any of the 300 OpenPhish benchmark URLs — or URLs with identical hostnames/patterns — present in the training data? Check for overlap between `augment_chain_phish.txt` and `fresh_openphish.txt`. If training URLs share apex domains with test URLs, the URL model is effectively memorizing rather than generalizing.
- **Label reliability**: OpenPhish is a live feed with no manual verification. What fraction of the 300 "phishing" URLs were actually still live and malicious at test time? Dead links (connection refused, NXDOMAIN) that happened to score high inflate TPR without proving detection.
- **Benign sample size and diversity**: 60 benign URLs is a small denominator for 0% FPR claims. The set must include: enterprise SSO/login pages, e-commerce checkout flows, URL shorteners, non-English domains, subdomains that pattern-match phishing (e.g., `secure.login.bank.com`), cloud infrastructure URLs (AWS, GCP, Azure load balancers), recently-registered legitimate sites, and high-value domains that phishers commonly impersonate. If the benign set is only Alexa-top-1000 homepages, it proves nothing about FP rates in the wild.
- **Threshold selected after seeing test data**: The threshold was lowered from 0.45 → 0.41 → 0.35 across multiple iterations. Each lowering was validated on the same benchmark set. This is threshold overfitting. The effective hold-out set no longer provides an independent estimate. Ask: what does FPR look like at 0.35 on a completely unseen benign set?
- **Single-run vs. repeated measurement**: Enrichment-based scoring is non-deterministic (network, caching, CDN routing). A single-run 99.67% number should be accompanied by a confidence interval across multiple runs. Has this been measured?

---

### 2. Training Data Integrity

- **Augmentation multiplier risk**: The phishing augmentation file is repeated ×150 (47,550 rows from 317 unique URLs). The benign augmentation is ×200 (59,800 rows from 299 unique URLs). These repetition factors dominate the training signal. A single malformed augmentation URL can teach the model a wrong n-gram pattern at enormous weight. Have every URL in both augmentation files been manually reviewed?
- **Domain leakage in augmentation**: The augmentation files contain patterns like `http://anthonytraders.in/filessss-8er78930000383/`. If `anthonytraders.in` also appears in the test set (via OpenPhish), the model has seen that domain 150 times in training. Verify no augmentation domains appear in any benchmark.
- **Microsoftonline FP and the fragility it reveals**: A single batch of 90 new phishing augmentation entries caused `login.microsoftonline.com` to spike from url_p=0.817 → 0.895, crossing the threshold. This was fixed by adding 8 microsoftonline URLs to benign augmentation. But this reveals a brittle tuning dynamic: **the model's behavior on high-value benign domains is controlled by explicit counter-examples, not principled generalization**. How many other important benign domains are one retraining away from becoming FPs? The fix for microsoftonline is essentially a whitelist entry disguised as a training sample.
- **Circular benign ceiling calibration**: The threshold (0.35) was chosen to be above the benign ceiling (0.255). The benign ceiling is computed from the same benign augmentation file. If the augmentation benign file happens to exclude a class of URLs that will appear in production (e.g., banking SSO, payment processors), the ceiling is artificially low and the threshold will produce FPs in production.
- **URLhaus exclusion**: URLhaus URLs were excluded from the benchmark after 17 gambling-site FNs were attributed to "label noise." Before accepting this explanation, verify: are those xxx365.com domains actually benign? A gambling site could legitimately be a phishing lure. The exclusion conveniently improved the TPR number.

---

### 3. URL Model (Character N-gram LR) Weaknesses

- **IDN homograph attacks**: Punycode domains (`xn--googIe-hsa.com` → visually `googlе.com`) may not be normalized before char n-gram extraction. A model trained on ASCII phishing patterns will produce low url_p for IDN homographs if the punycode form doesn't match learned patterns.
- **URL canonicalization gaps**: The URL normalizer (`canonicalize_url_for_model`) — what edge cases does it handle? URLs with unusual encodings (`%2F` in path), mixed-case schemes (`HTTPS://`), trailing slashes, query string ordering, fragment identifiers. A phisher who knows the normalization logic can craft URLs that score low.
- **N-gram saturation on long URLs**: Very long URLs (common in tracking pixels, OAuth flows, SSO callbacks) produce thousands of 2–4 char n-grams. HashingVectorizer with 2^18 bins will see significant collision. Has collision rate been measured for URLs >200 chars?
- **Short domain evasion**: Single-word domains like `apple.co` or `paypa1.com` produce few distinctive n-grams. The 2-char minimum gram `pa`, `ay`, `yp` etc. are common across legitimate and phishing URLs. Test url_p for character-substitution typosquats (`0` for `o`, `1` for `l`, `rn` for `m`).
- **Adversarial prefix/suffix**: A phisher can prepend `google-secure-login.` to a malicious domain. Does the model correctly weight the apex vs. the prefix? Or does seeing `google` in the URL lower url_p?

---

### 4. Operational Model Weaknesses

- **Domain age NaN handling**: New domains (WHOIS lookup fails, or domain registered today) produce `domain_age_days = NaN`. HGB handles NaN natively, but what direction does it impute? If HGB treats NaN as "old domain" rather than "new domain," freshly-registered phishing domains will score lower than they should.
- **Feature staleness at inference time**: The operational model was trained on enrichment data collected at a point in time. Features like `cert_age_days`, `asn`, `latitude` are snapshots. A phishing site that rotates infrastructure (common for bulletproof hosting) may present different ASN/GeoIP at inference time than at training time. How robust is the model to infrastructure rotation?
- **DOM feature coverage**: `title_brand_mismatch`, `form_action_mismatch`, `favicon_domain_mismatch` all require successful HTTP fetch and HTML parsing. Sites that block scrapers (Cloudflare JS challenge, bot detection) will produce NaN for these features. Has the model's behavior been tested when all DOM features are NaN simultaneously?
- **GeoIP binning**: `latitude` and `longitude` as continuous features in a tree model create irregular splits. The model may have learned "phishing comes from latitude 37.7749" (a GeoIP default for unknown US IPs) rather than a generalizable geographic signal. What is the feature importance of lat/lon, and does it make sense?
- **HTTP status code leakage**: If a phishing site is taken down between training enrichment and deployment, it returns 404/410. The operational model may have learned "status 200 = phishing" spuriously if training data was enriched while sites were live. Test: what is op_p for a 404-returning URL?

---

### 5. Fusion Layer and Threshold Calibration

- **Mean fusion amplifies URL model failures**: `mean(url_p, op_p)` means a URL with url_p=0.9 and op_p=0.0 (site is operational, certificate is fine, WHOIS shows old domain) scores fusion=0.45 → flagged. Is this desirable? The URL model firing alone should arguably not be sufficient for a verdict, especially for legitimate but URL-pattern-suspicious sites (SSO providers, payment processors).
- **Threshold 0.35 safety margin is thin**: Benign ceiling = 0.255, threshold = 0.35, margin = 0.095. If the URL model's benign ceiling shifts by 0.10 on production traffic (due to URL patterns not in augmentation), the system will produce FPs. A 9.5-point margin with a model trained partly on hand-picked augmentation is not wide.
- **No calibration curve**: Are the model's probability outputs actually calibrated? LR outputs are better calibrated than tree models, but with a HashingVectorizer and high-repeat augmentation, the probabilities may be poorly calibrated in the tail regions (near 0 and near 1). A Platt scaling or isotonic regression calibration layer was not mentioned.
- **Threshold is per-run, not per-domain-category**: A 0.35 threshold applied uniformly means a 0.34-scoring banking phish is released. A domain-category-aware threshold (stricter for commerce/banking patterns) would reduce this risk.

---

### 6. Content Gate Limitations

- **Brand impersonation signal is symmetric**: The brand impersonation signal fires when a domain's HTML contains ≥2 major brand names AND the domain is not one of those brands. This correctly flags `amazvistore.com` when it displays Amazon content. But it will also trigger for **legitimate comparison shopping sites, affiliate marketers, and review sites** (e.g., `techcrunch.com` reviewing Apple and Google products). The gate fires for these but the content_score remains below 0.35 because no cart/credential signals fire — verify this holds for high-volume review/affiliate domains.
- **Commerce keyword trigger is domain-name only**: `_should_trigger` fires for any domain with `store`, `shop`, `buy`, `deal`, etc. in the hostname. This is a wide net. `shopify.com` triggered the gate and scored brand_impersonation:instagram,walmart because Shopify's homepage lists customer brands. The gate did not FP (boosted score=0.186), but this is a narrow margin. What about `shopify.com/checkout` or a Shopify-hosted merchant storefront?
- **Fetch-dependent reliability**: Content gate fetches live HTML. If a phishing site is behind a WAF or Cloudflare, the gate fetches a challenge page, not the real content. The gate will undercount signals for sophisticated phishing infrastructure, while potentially triggering on legitimate sites that happen to pass Cloudflare.
- **`gray_lower=0.08` lower bound**: URLs scoring below 0.08 do not trigger the gray-zone condition. A very convincing phishing site with a legitimate-looking URL (low url_p) and clean infrastructure (low op_p) will score below 0.08 and skip the gate entirely. The gate only catches borderline cases, not the most evasive attacks.
- **Content gate score is not validated**: The `_CONTENT_BOOST_WEIGHT = 0.45` constant was chosen without empirical validation. What is the actual precision/recall of the content gate in isolation? Without a labeled dataset of gray-zone URLs, there is no basis for claiming this weight produces good outcomes.

---

### 7. Production Deployment Risks

- **Model file integrity**: `url_char_lr.joblib` and `hgb_operational.joblib` are loaded via `joblib.load()`. Joblib files can execute arbitrary code on deserialization. If these files are stored in a location writable by other processes, a supply-chain or local privilege escalation attack can compromise the detector. Are model files stored with restricted permissions, checksummed, and loaded from a read-only path?
- **Threading under load**: `score_batch.py` uses `ThreadPoolExecutor` with default 6 workers. Each worker does synchronous `requests.get()` with 8-second timeout. Under high load with slow URLs, threads can block. Is there a per-request timeout that guarantees forward progress? What happens when all 6 threads are blocked on slow hosts?
- **`verify=False` in content gate HTTP fetch**: `requests.get(..., verify=False)` disables SSL certificate verification. This was done to allow fetching phishing sites with invalid certs. But it also means the system is vulnerable to MITM in environments with intercepting proxies (corporate networks, CI environments). The urllib3 InsecureRequestWarning should be suppressed or this risk documented.
- **URL shortener resolution leaks intent**: `resolve_short_url()` resolves URL shorteners before enrichment. This sends an HTTP HEAD/GET request to `t.co`, `bit.ly`, etc. and then to the destination. If the destination is a honeypot-aware phishing kit, the resolution reveals that a scanner is checking the link. The phishing kit can then serve clean content to the scanner IP and malicious content to victims.
- **No rate limiting or circuit breaker**: If the enrichment pipeline is called on a batch of 10,000 URLs simultaneously, it will generate 10,000+ outbound HTTP requests, WHOIS lookups, and DNS queries. Is there a rate limiter? This is both a self-DoS risk and a risk of getting the egress IP blocked by WHOIS providers.
- **Enrichment caching**: Is enrichment cached? If yes — for how long? A phishing site that changes its content after being cached as benign will continue to score low. If no — every repeat query re-enriches, which is expensive but correct.

---

### 8. Adversarial Robustness

- **Evasion via long benign-looking paths**: A phisher can construct `https://legitimate-cdn.com/redirect?url=https://evil.com/phish`. If `score_batch.py` scores the original URL (not the redirect destination), the CDN apex domain produces low url_p and clean operational features. The redirect destination is never scored. Verify how open redirects are handled.
- **Subdomain farming**: `phishing.google.com.evil.com` — the URL char model sees `google`, `com` as n-grams. Does this lower url_p? The operational model's `subdomain_depth` and `subdomain_brand_count` features should catch this, but test explicitly.
- **Newly registered lookalike domains**: A domain registered yesterday (`amazon-secure-verify.com`) has domain_age_days=0 or NaN. Combined with HTTPS (free cert via Let's Encrypt), it may score lower than expected on op_p if cert_age_days is also near 0 and the model hasn't learned this combination.
- **Content gate evasion**: A sophisticated phisher can render content dynamically (JavaScript-rendered, behind login wall) so that raw HTML contains no brand keywords, no login forms, and no cart buttons. The content gate will find nothing and not boost the score. The gate is only effective against unsophisticated or commodity phishing kits.

---

### 9. Specific Test Cases to Run Before Deployment

The reviewer should verify the following URLs produce expected verdicts (all should be benign — score < 0.35):

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
https://accounts.google.com/signin/v2/identifier
https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go
https://www.paypal.com/signin
https://appleid.apple.com/auth/authorize
https://checkout.shopify.com/
https://www.amazon.com/ap/signin
https://signin.aws.amazon.com/signin
https://github.com/login
https://app.slack.com/signin
```

And the following should score ≥ 0.35 (phishing):
```
http://paypa1-secure-login.com/signin
https://amazon-verify-account.xyz/login
http://apple-id-verify.tk/
https://secure-bankofamerica.login-verify.com/
http://netflix-billing-update.site/
```

If any of the benign URLs score ≥ 0.35, document the url_p, op_p, and the specific augmentation entries that drove the score.

---

### 10. Documentation and Reproducibility

- **Training script reproducibility**: Can another engineer reproduce the trained models exactly from scratch given only the repository? Are random seeds fixed? Is the training data versioned?
- **Model versioning**: Are the `.joblib` files versioned (hash-locked) in deployment? If a model is retrained and deployed without re-running the full benchmark, silent performance degradation can occur.
- **Threshold change protocol**: The threshold was changed from 0.45 → 0.35 across iterations. Is there a documented decision record for each threshold change, including: who approved it, what FPR data justified the reduction, and what the safety margin was at each step?
- **Content gate is opt-in**: The `--content-gate` flag is off by default. Production deployments that don't enable it will miss the gray-zone coverage. Is this intentional? Should it be on by default?
- **`verify=False` is silent**: The SSL verification disable in content gate produces no log entry. In production, all security-relevant decisions (gate triggered, fetch failed, signals found) should be logged at INFO level with the URL and scores.

---

## Summary of Highest-Priority Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| Threshold overfitting to benchmark set | High | Medium | Re-evaluate on completely unseen benign URLs |
| Microsoftonline-style FP from future retraining | High | Medium | Automated benign ceiling test on every retrain |
| Benchmark temporal leakage (training/test overlap) | High | Low-Medium | Deduplicate augment domains against test set |
| Content gate FP on review/affiliate sites | Medium | Medium | Test 50+ comparison/affiliate URLs |
| DOM features all-NaN behavior (bot-blocked sites) | Medium | Medium | Run benchmark with DOM features zeroed out |
| `verify=False` in production fetch | Medium | Low | Log warning, document risk, consider env-based toggle |
| Open redirect evasion | High | High | Score redirect destination, not just submitted URL |
| JavaScript-rendered phishing evades content gate | Medium | High | Document as known limitation; do not overclaim gate coverage |
| Model file deserialization risk | Critical | Low | Checksum model files; restrict filesystem permissions |
| No rate limiting on enrichment | Medium | Medium | Add semaphore or token bucket in production wrapper |
