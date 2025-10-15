# 🔒 Phishing Email Detector

**Automated email threat detection using real-time threat intelligence and risk scoring.**

> 📚 **[Complete Documentation Index →](docs/README.md)**

---

## ⚡ Quick Start (2 Minutes)

```bash
# 1. One command to rule them all
python run.py demo --once

# 2. View results
# Dashboard auto-opens at http://localhost:8501
```

**That's it!** See **[QUICK_START.md](QUICK_START.md)** for details.

---

## ✨ Key Features

- **📧 Email Monitoring** - Real-time Gmail analysis with risk scoring (0-100)
- **🎯 Threat Detection** - Matches against 50,000+ known phishing URLs
- **🚀 Async Enrichment** - 5-10x faster URL analysis with parallel processing
- **📊 Live Dashboard** - Interactive web interface with auto-refresh
- **🔍 Smart Scoring** - Multi-factor risk analysis (liveness, domain age, TLD, keywords)
- **🎬 Demo Mode** - One-command setup with continuous monitoring

---

## 🎯 What This Does

1. **Fetches your Gmail** → Extracts URLs from emails
2. **Checks threat feeds** → PhishTank, URLhaus, OpenPhish
3. **Enriches URLs** → WHOIS, GeoIP, SSL, network data
4. **Calculates risk** → 0-100 score based on 5 factors
5. **Shows dashboard** → Visual interface with risk breakdown

**Result:** Know immediately if an email contains known phishing URLs or suspicious links.

---

## 📋 Requirements

- **Python 3.11+**
- **Gmail account** (for email monitoring)
- **2 GB disk space** (for threat database)
- **Internet connection** (for threat feeds)

---

## 🚀 Installation

```bash
# Clone repository
git clone <repository-url>
cd phishing-detector

# Auto-setup (does everything)
python run.py demo --once
```

**Manual setup:**
```bash
python run.py setup    # Create database + download threats
python run.py auth     # Authenticate Gmail
```

See [QUICK_START.md](QUICK_START.md) for step-by-step guide.

---

## 📖 Main Commands

```bash
python run.py demo              # Auto-everything + continuous monitoring
python run.py demo --once       # Test once (recommended first run)
python run.py auth              # Authenticate Gmail
python run.py bootstrap         # Analyze emails (one-shot)
python run.py dashboard         # Open web interface
```

**Or use interactive menu:**
```bash
python start.py
```

Full command reference: `python run.py --help`

---

## 📊 Dashboard Features

Access at **http://localhost:8501** (auto-opens in demo mode)

**Primary Tab - Email Monitoring:**
- 🚨 Critical/High/Medium/Low risk counts
- 📈 Risk distribution and timeline charts
- 📧 Email list with risk scores
- 🔗 URL analysis (threat feed matches highlighted)
- 🔍 Detailed drill-down for each email/URL

See [Email Dashboard Guide](docs/guides/EMAIL_DASHBOARD_GUIDE.md) for full feature list.

**Other Tabs:**
- Threat Overview - High-level threat statistics
- Analytics - Deep-dive charts and geographic maps
- Data Explorer - Browse 50,000+ threats with advanced filters
- Search - Quick URL/domain/IP lookup

---

## 🔧 Configuration (Optional)

### API Keys for Enhanced Features

Create `.env` file in project root:

```bash
# Higher PhishTank rate limits (optional)
PHISHTANK_API_KEY=your_key_here

# URLhaus malware data (recommended)
URLHAUS_API_KEY=your_key_here
```

**Get keys:** [PhishTank](https://phishtank.org/api_register.php) | [URLhaus](https://auth.abuse.ch/)

### Gmail Credentials

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com)
2. Save as `app/detector/credentials.json`
3. Run: `python run.py auth`

See [Detector README](app/detector/README.md) for detailed Gmail setup.

---

## 📁 Project Structure

```
phishing-detector/
├── 📄 README.md (this file)        ← Project overview
├── 📄 QUICK_START.md               ← 4 essential commands
├── 🎬 start.py                     ← Interactive menu
├── ⚙️  run.py                       ← Command runner
│
├── 📚 docs/
│   ├── README.md                   ← Documentation index
│   ├── guides/                     ← User guides
│   │   ├── EMAIL_DASHBOARD_GUIDE.md
│   │   ├── DEMO_MODE_GUIDE.md
│   │   ├── DOCUMENTATION_MAP.md
│   │   └── COMMIT_GUIDE.md
│   └── technical/                  ← Technical docs
│       └── TECHNICAL_REPORT.md
│
├── 🔧 utils/                        ← Utility scripts
│   ├── check_duplicates.py
│   ├── check_url_matching.py
│   └── debug_emails.py
│
└── app/                            ← Source code
    ├── database/                   ← Threat intelligence
    │   ├── README.md               ← Database quick start
    │   └── Documentation/          ← Technical details
    ├── detector/                   ← Email analysis
    │   ├── README.md               ← Detector quick start
    │   └── Documentation/          ← Technical details
    └── dashboard/                  ← Web interface
        ├── README.md               ← Dashboard quick start
        └── Documentation/          ← Technical details
```

**Navigate:** [📚 Full Documentation Index](docs/README.md)

---

## 📖 Documentation

### By Role

**👤 End User** (just want to use it):
- Start: [QUICK_START.md](QUICK_START.md)
- Dashboard: [EMAIL_DASHBOARD_GUIDE.md](docs/guides/EMAIL_DASHBOARD_GUIDE.md)
- Demo Mode: [DEMO_MODE_GUIDE.md](docs/guides/DEMO_MODE_GUIDE.md)

**👨‍💻 Developer** (want to understand/modify):
- Overview: [Technical Report](docs/technical/TECHNICAL_REPORT.md)
- Database: [app/database/README.md](app/database/README.md)
- Detector: [app/detector/README.md](app/detector/README.md)
- Dashboard: [app/dashboard/README.md](app/dashboard/README.md)

**🔬 Researcher** (want full details):
- Complete Index: [docs/README.md](docs/README.md)
- Database Guide: [DATABASE_GUIDE.md](app/database/Documentation%20&%20Sources%20Research/DATABASE_GUIDE.md)
- Detector Guide: [DETECTOR_GUIDE.md](app/detector/Documentation/DETECTOR_GUIDE.md)

### By Topic

| Topic | Quick Start | Technical Details |
|-------|-------------|-------------------|
| **Email Monitoring** | [EMAIL_DASHBOARD_GUIDE.md](docs/guides/EMAIL_DASHBOARD_GUIDE.md) | [DETECTOR_GUIDE.md](app/detector/Documentation/DETECTOR_GUIDE.md) |
| **Database** | [app/database/README.md](app/database/README.md) | [DATABASE_GUIDE.md](app/database/Documentation%20&%20Sources%20Research/DATABASE_GUIDE.md) |
| **Dashboard** | [app/dashboard/README.md](app/dashboard/README.md) | [DASHBOARD_GUIDE.md](app/dashboard/Documentation/DASHBOARD_GUIDE.md) |
| **Overall System** | [QUICK_START.md](QUICK_START.md) | [TECHNICAL_REPORT.md](docs/technical/TECHNICAL_REPORT.md) |

---

## 🐛 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| No emails showing | Run `python utils/debug_emails.py --check` |
| URL not matching threat feed | Run `python utils/check_url_matching.py <URL>` |
| Duplicate enrichment | Fixed - automatic detection now |
| Database errors | Run `python utils/check_duplicates.py` |

**Detailed troubleshooting:** See module READMEs or run `python start.py` → option 5 (Help)

---

## Limitations and Future Work

### Current Limitations

#### WHOIS Data Coverage (31%)
**Issue:** Only 31% of URLs have complete WHOIS data (registrar, creation_date)  
**Cause:** 
- WHOIS privacy protection services (69% of domains)
- TLD-specific restrictions (.dev, .br, .tl)
- Subdomain hosting (blogspot, pages.dev) returns parent domain data

**Impact:** Domain age scoring relies on incomplete data

**Mitigation:** System uses alternative signals (first_seen dates, TLD/platform scoring)

#### Content Analysis Not Implemented
**Issue:** No analysis of page screenshots, HTML structure, or visual similarity  
**Cause:** Out of scope for current implementation (focused on metadata enrichment)

**Impact:** Visually identical phishing pages not detected

**Future Work:** Integrate OCR + computer vision for login page detection

#### Gmail-Only Email Integration
**Issue:** Only supports Gmail accounts via OAuth 2.0  
**Cause:** Gmail API integration design choice

**Impact:** Enterprise email platforms (Exchange, Office 365) not supported

**Future Work:** Add IMAP/SMTP support for broader compatibility

#### False Positive Rate (2%)
**Issue:** Some legitimate sites flagged as high-risk  
**Examples:**
- Legitimate .xyz domains with login portals
- Startups using .click TLD with "verify" pages

**Mitigation:** Manual whitelist feature or domain reputation integration

**Future Work:** Integrate domain reputation services (Alexa, Majestic, Tranco)

### Future Enhancements

#### 1. Machine Learning Integration
- Train classifier on 41 enriched features + URL lexical analysis
- Algorithms: Random Forest, Gradient Boosting, Neural Networks
- **Expected Improvement:** 97%+ accuracy (vs 94% rule-based)

#### 2. Real-Time Threat Monitoring
- WebSocket API for live threat feed updates
- SOC dashboard integration
- **Benefit:** Zero-day threat detection within minutes

#### 3. Campaign Clustering
- Group related threats by ASN, registrar, nameservers
- Identify coordinated phishing campaigns
- **Output:** Campaign reports with shared infrastructure

#### 4. SIEM/SOAR Integration
- REST API webhooks
- Automated firewall/proxy blocking
- **Target Platforms:** Splunk, Elastic SIEM, Cortex XSOAR

#### 5. Subdomain Tracking
- Passive DNS database integration
- Track subdomain creation dates independently
- **Impact:** Better detection of subdomain-based phishing

#### 6. Historical Trend Analysis
- Time-series analysis of threat volumes
- Predictive analytics for campaign surges
- **Use Case:** Resource planning for holiday season attacks

### Scalability Considerations

| Scale | URLs | Current Performance | Bottleneck | Solution |
|-------|------|---------------------|------------|----------|
| **Small** | <100K | 15-18 hours | WHOIS rate limits | Current architecture sufficient |
| **Medium** | 100K-1M | 6-8 days | SQLite write performance | PostgreSQL + distributed workers |
| **Large** | 1M+ | Weeks | Network I/O, single machine | Kubernetes + Kafka + Elasticsearch |

---

## 📊 System Performance

- **Email Analysis:** 5-10 URLs/email in ~8 seconds (parallel)
- **Threat Matching:** Instant (indexed database lookup)
- **URL Enrichment:** ~1 second/URL (async mode)
- **Dashboard Load:** <1 second (cached)

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional threat feed integrations
- Machine learning classifiers
- Dashboard enhancements
- Performance optimizations

See [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for architecture details.

## 💻 System Requirements

**Minimum:** Python 3.11+, 4GB RAM, 500MB disk  
**Recommended:** 4+ cores, 8GB RAM, 2GB disk

Supports: Linux, macOS, Windows (WSL)

---

## License

See [LICENSE](LICENSE) file for details.

---

## Citation

If you use this project in research, please cite:

```
@misc{phishing-detector,
  author = {[Your Name]},
  title = {Phishing Detector: Threat Intelligence System},
  year = {2025},
  publisher = {GitHub},
  url = {https://github.com/[username]/phishing-detector}
}
```

---

## 🙏 Acknowledgments

- **OpenPhish, PhishTank, URLhaus** - Threat feeds
- **MaxMind** - GeoLite2 databases
- **Google** - Gmail API

---

## 🔗 Quick Links

- 📚 [Complete Documentation Index](docs/README.md)
- ⚡ [Quick Start Guide](QUICK_START.md)
- 📧 [Email Monitoring Guide](docs/guides/EMAIL_DASHBOARD_GUIDE.md)
- 🎬 [Demo Mode Guide](docs/guides/DEMO_MODE_GUIDE.md)
- 🗄️ [Database Documentation](app/database/README.md)
- 📊 [Dashboard Documentation](app/dashboard/README.md)
- 🔍 [Detector Documentation](app/detector/README.md)
- 📖 [Technical Report](docs/technical/TECHNICAL_REPORT.md)

---

**Ready to detect phishing threats!** Start with: `python run.py demo --once` 🚀
