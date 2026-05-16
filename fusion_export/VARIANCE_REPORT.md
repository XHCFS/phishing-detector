# Live Performance Variance Report

**Date:** 2026-05-15  
**Model version:** fusion v1.7.0 (url_char_lr + hgb_operational, threshold=0.35)  
**Test method:** 5 independent random samples of 50 URLs each, scored against live enrichment, drawn from sources not seen during training or the original OpenPhish benchmark.

---

## Method

Previous benchmarks reported 99.67% TPR on 300 OpenPhish URLs — a single feed, single run. This report answers: *does the model generalize to phishing URLs from a different source, and what is the real FPR on unseen benign URLs?*

**Phishing source:** PhishTank verified+online feed (60,283 URLs as of 2026-05-15). All URLs in the training augmentation files and the OpenPhish benchmark were excluded before sampling, leaving 60,279 fresh URLs. Five non-overlapping random samples of 50 URLs each were drawn (seed=42). URL shorteners (`l.ead.me`, `q-r.to`, `bit.ly`) were excluded to eliminate confounding from redirect chains.

**Benign source:** Internal benign dataset (50,000 URLs, diverse sources: newsletters, CDNs, enterprise SaaS, APIs, corporate portals). All URLs already in the augmentation or live_benign test set were excluded. Five non-overlapping random samples of 50 URLs each were drawn (seed=99).

Each sample was scored independently: full live enrichment (WHOIS, GeoIP, TLS, HTTP) + dual model scoring + mean fusion. Threshold: 0.35.

---

## TPR Results — Fresh PhishTank URLs

| Sample | Caught | Total | TPR |
|--------|--------|-------|-----|
| 1 | 45 | 50 | **90.0%** |
| 2 | 46 | 50 | **92.0%** |
| 3 | 46 | 50 | **92.0%** |
| 4 | 50 | 50 | **100.0%** |
| 5 | 46 | 50 | **92.0%** |
| **Total** | **233** | **250** | **93.2%** |

**Mean TPR: 93.2% | Range: 90–100% | Std dev: 3.7%**

### Context: Why lower than OpenPhish?

The 99.67% OpenPhish figure is not wrong — it reflects real performance on that feed. The 6.4-point gap to PhishTank's mean is explained by differences in the URL populations:

OpenPhish skews toward **active credential phishing kits** — fresh domains with suspicious URLs, non-standard ASNs, and newly-issued Let's Encrypt certs. These score strongly on both models.

PhishTank includes a broader mix, particularly **platform phishing** — attacks hosted on legitimate SaaS infrastructure (GitHub Pages, Adobe Portfolio, Webflow, Weebly, Square Sites). These produce clean operational features because the hosting platform is legitimate. Representative PhishTank FNs:

| URL | url_p | op_p | deploy_p | Why missed |
|-----|-------|------|----------|------------|
| `https://entry5300-js2024r1.usercontent.dev/` | 0.407 | 0.073 | 0.240 | GitHub usercontent CDN; clean op features |
| `https://store108574004.company.site/` | 0.516 | 0.026 | 0.271 | Square Sites hosting; legitimate platform ASN |
| `https://toddb007.myportfolio.com/` | 0.009 | 0.001 | 0.005 | Adobe Portfolio; very clean URL + op features |
| `https://docuslots-port-folio.myportfolio.com/` | 0.009 | 0.001 | 0.006 | Same pattern |
| `https://kajendiranm.github.io/Airbnb-Clone` | (variable) | — | — | GitHub Pages; caught in some runs, missed in others |

**Pattern**: Platform phishing is the primary failure mode. The operational model cannot distinguish a phishing page hosted on Adobe Portfolio from a legitimate portfolio page — the ASN, cert, domain age, and HTTP status are identical.

---

## FPR Results — Fresh Benign URLs

| Sample | FPs | Total | FPR |
|--------|-----|-------|-----|
| 1 | 1 | 50 | **2.0%** |
| 2 | 2 | 50 | **4.0%** |
| 3 | 1 | 50 | **2.0%** |
| 4 | 1 | 50 | **2.0%** |
| 5 | 1 | 50 | **2.0%** |
| **Total** | **6** | **250** | **2.4%** |

**Mean FPR: 2.4% | Range: 2–4% | Std dev: 0.9%**

### False positive breakdown

| URL | url_p | op_p | deploy_p | Root cause |
|-----|-------|------|----------|------------|
| `jbhunt-my.sharepoint.com/unsubscribe` | 0.996 | 0.000 | 0.498 | `*-my.sharepoint.com` pattern |
| `dktire-my.sharepoint.com/` | 0.993 | 0.000 | 0.496 | `*-my.sharepoint.com` pattern |
| `jcdecaux-my.sharepoint.com/` | 0.993 | 0.000 | 0.496 | `*-my.sharepoint.com` pattern |
| `securemail.pro/` | 0.837 | 0.007 | 0.422 | Security-keyword domain |
| `profil.monxtra.be/` | 0.999 | 0.000 | 0.500 | European ccTLD + `profil` subdomain |
| `netu.tv/` | 0.368 | 0.600 | 0.484 | Suspicious ASN drives op_p; `.tv` TLD |

**3 of 6 FPs are the same systematic pattern**: Microsoft SharePoint personal sites use the format `companyname-my.sharepoint.com`. The `-my.` subdomain prefix closely matches phishing patterns like `paypal-my.secure.com`, driving url_p to near 1.0. Since op_p for SharePoint is near 0 (Microsoft's infrastructure is clean), mean fusion = ~0.50, well above the threshold. **Mitigation: add 5–10 `*-my.sharepoint.com` variants to `augment_hard_benign.txt` and retrain.**

---

## Comparison: OpenPhish vs. PhishTank

| Metric | OpenPhish (n=300) | PhishTank (5×50) |
|--------|-------------------|-----------------|
| TPR | 99.67% | 90–100% (mean 93.2%) |
| FPR (original 60 benigns) | 0.0% | — |
| FPR (fresh 5×50 benigns) | — | 2–4% (mean 2.4%) |
| Primary FN pattern | `amazvistore.com` (stale label) | Platform phishing (GitHub, Adobe, Square) |
| Primary FP pattern | None | `*-my.sharepoint.com` |

The OpenPhish 0% FPR on 60 benign URLs underestimated production FPR. With a broader benign set, FPR is 2–4%. This is the honest number to report.

---

## Summary

The model's real-world performance on unseen live data:

- **TPR: 90–100%, mean 93%** (across different phishing populations)
- **FPR: 2–4%, mean 2.4%** (on diverse enterprise/consumer benign URLs)

The 99.67% OpenPhish figure remains valid for that specific feed type (credential phishing kits on fresh domains), but is not representative of the full attack surface. The honest deployed expectation is:

> **~93% of phishing URLs caught, ~2–4% of benign URLs incorrectly flagged**

Known gap: platform phishing (attacks hosted on legitimate SaaS platforms) systematically evades both models because the hosting infrastructure is indistinguishable from legitimate use.

Known FP class: Microsoft SharePoint personal sites (`*-my.sharepoint.com`) — fixable with a one-line benign augmentation addition.
