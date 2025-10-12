# phishing-detector
This is a program that detects, and groups phishing emails using threat intelligence from multiple public feeds.

## Features

- **Threat Intelligence Database** - Collects data from OpenPhish, PhishTank, and URLhaus
- **Enrichment Pipeline** - Adds GeoIP, WHOIS, SSL, and network information
- **Detection & Analysis** - Identifies phishing patterns and threats
- **Dashboard** - Visual interface for monitoring threats

---

# Setup Guide

## 1. Requirements
- Python 3.11 or newer  
- Bash shell (Linux, macOS, or WSL on Windows)
- Internet connection (for downloading threat feeds)

---

## 2. Quick Installation

Clone the repository and enter the folder:

```bash
git clone <repository-url>
cd phishing-detector
```

Run the automated setup:

```bash
# Using the centralized runner (recommended)
python run.py setup

# Or using shell scripts
./setup.sh          # Bash
./setup.fish        # Fish shell
```

Start the application:

```bash
# Using the centralized runner (recommended)
python run.py api

# Or using shell scripts
./run.sh            # Bash
./run.fish          # Fish shell
```

The setup will:
- Create a Python virtual environment
- Install all dependencies
- Initialize the threat feeds database
- Populate with initial threat data

---

## 3. Database Setup

The threat intelligence database is automatically initialized by `setup.sh`. For manual setup or advanced configuration, see:

**[Database Setup Guide](app/database/README.md)** - Complete database documentation

**Quick Database Commands:**
```bash
# Create and populate raw threat database
python -m app.database.rawdb
python -m app.database.grabrawdata

# Create enriched database
python -m app.database.db

# Run enrichment (test with 10 URLs)
python -m app.database.enrich --limit 10
```

---

## 4. Configuration (Optional)

### API Keys

For enhanced functionality, create a `.env` file in the project root:

```bash
# Optional - for higher PhishTank rate limits
PHISHTANK_API_KEY=your_key_here

# Required for URLhaus malware data
URLHAUS_API_KEY=your_key_here
```

**Get API Keys:**
- PhishTank: https://phishtank.org/api_register.php
- URLhaus: https://auth.abuse.ch/

---

## 5. Usage

### Start the Application
```bash
# Centralized runner (recommended)
python run.py api              # FastAPI server
python run.py dashboard        # Streamlit dashboard

# Shell scripts
./run.sh                       # FastAPI (Bash)
./run.fish                     # FastAPI (Fish)
./run_dashboard.sh             # Dashboard (Bash)
./run_dashboard.fish           # Dashboard (Fish)
```

Access the API at: http://localhost:8000  
Access the dashboard at: http://localhost:8501

### Update Threat Feeds
```bash
# Centralized runner (recommended)
python run.py fetch                                    # Update raw threat feeds
python run.py enrich --limit 1000 --skip-existing     # Enrich new URLs

# Direct module calls
python -m app.database.grabrawdata
python -m app.database.enrich --limit 1000 --skip-existing
```

---

## Project Structure

```
phishing-detector/
├── app/
│   ├── database/           # Threat intelligence database system
│   │   ├── README.md       # Database setup guide
│   │   ├── rawdb.py        # Raw database schema
│   │   ├── grabrawdata.py  # Fetch threat feeds
│   │   ├── db.py           # Enriched database schema
│   │   ├── enrich.py       # Enrichment pipeline
│   │   └── Documentation & Sources Research/
│   │       ├── DATABASE_GUIDE.md  # Complete technical docs
│   │       └── Data Sources.md    # Threat feed details
│   ├── detector/           # Phishing detection logic
│   └── dashboard/          # Web interface
├── run.py                  # Centralized runner (recommended)
├── commands.py             # Command reference
├── setup.sh / setup.fish   # Setup scripts
├── run.sh / run.fish       # Start API scripts
├── run_dashboard.sh / run_dashboard.fish  # Start dashboard scripts
└── requirements.txt        # Python dependencies
```

---

## Documentation

- [Database Setup Guide](app/database/README.md) - Quick start and commands
- [Complete Database Documentation](app/database/Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md) - Technical details (985 lines)
- [Data Sources](app/database/Documentation%20%26%20Sources%20Research/Data%20Sources.md) - Threat feed specifications

---

## Command Reference

For a complete list of all available commands and options:

```bash
# View all commands
python run.py --help

# View command-specific help
python run.py setup --help
python run.py enrich --help
python run.py api --help

# Quick reference
python commands.py
```

### Common Commands

```bash
# Setup and initialization
python run.py setup                    # Full setup
python run.py setup --fast-enrich      # Quick setup
python run.py db                       # Init databases only

# Data management
python run.py fetch                    # Fetch threat feeds
python run.py enrich --limit 100       # Enrich 100 URLs
python run.py enrich --skip-existing   # Skip already enriched

# Email detection
python run.py auth                     # Gmail authentication
python run.py emails --count 10        # Fetch 10 emails
python run.py enrich-emails            # Enrich fetched emails

# Services
python run.py api                      # Run API server
python run.py api --reload             # Run with auto-reload
python run.py dashboard                # Run dashboard
```

## Troubleshooting

### Setup Issues

**"Virtual environment not found"**
```bash
python run.py setup
# Or: ./setup.sh (Bash) or ./setup.fish (Fish)
```

**"Database initialization failed"**
```bash
python run.py db
# Or manually:
# python -m app.database.rawdb
# python -m app.database.db
```

**"No threat data"**
```bash
# Ensure you have internet connection, then:
python run.py fetch
# Or: python -m app.database.grabrawdata
```

### More Help

See [Database README](app/database/README.md) for database-specific troubleshooting.

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

## Documentation

### Module Documentation
- **[Database Module](app/database/README.md)** - Threat feed collection and enrichment
  - [Complete Database Guide](app/database/Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md) 
  - [Data Sources](app/database/Documentation%20%26%20Sources%20Research/Data%20Sources.md)

- **[Detector Module](app/detector/README.md)** - Email analysis and risk scoring
  - [Complete Detector Guide](app/detector/Documentation/DETECTOR_GUIDE.md) 

- **[Dashboard Module](app/dashboard/README.md)** - Web visualization
  - [Complete Dashboard Guide](app/dashboard/Documentation/DASHBOARD_GUIDE.md) 

- **[App Module](app/README.md)** - Main application and API

### Technical Documentation
- **[Technical Report](TECHNICAL_REPORT.md)**
  - Introduction and background
  - System architecture
  - Data sources and enrichment methodology
  - Risk scoring algorithm design
  - Implementation details
  - Evaluation and results
  - Limitations and future work

- **[Presentation Slides](PRESENTATION.pdf)** (10 slides, LaTeX Beamer)
  - Clean, minimalist design with focused content
  - Problem statement with compelling statistics
  - Solution architecture and risk scoring methodology
  - Real phishing detection example walkthrough
  - Performance metrics and key achievements
  - Future enhancements and conclusion
  - Source: [PRESENTATION.tex](PRESENTATION.tex) | Compilation guide: [PRESENTATION_README.md](PRESENTATION_README.md)

- **[Risk Scoring Summary](RISK_SCORING_SUMMARY.md)** - Implementation details

### Total Documentation
Over **15,000 words** of comprehensive technical documentation covering:
- Setup and installation
- Architecture and design
- API reference
- Troubleshooting
- Research and evaluation

---

## Performance

### Enrichment Speed
- **Sequential:** 4-6 seconds per URL
- **Async (default):** ~1 second per URL (10x speedup)
- **Full dataset (52,000 URLs):** 15-18 hours

### Dashboard Load Times
- **First load:** 2-4 seconds
- **Cached:** <1 second

### Email Analysis
- **5-10 URLs per email:** 8-10 seconds (parallel enrichment)
- **Typical Gmail inbox:** 25 emails processed in ~4 minutes

---

## System Requirements

### Minimum
- **CPU:** 2 cores
- **RAM:** 4 GB
- **Disk:** 500 MB (database + code)
- **OS:** Linux, macOS, or Windows (WSL)

### Recommended
- **CPU:** 4+ cores (for parallel enrichment)
- **RAM:** 8 GB
- **Disk:** 2 GB (with room for growth)
- **Internet:** Broadband (for threat feeds and enrichment APIs)

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

**Areas for Contribution:**
- Additional threat feed integrations
- Machine learning classifiers
- Dashboard improvements
- Performance optimizations
- Bug fixes and testing

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

## Acknowledgments

- **OpenPhish** - Free phishing feed
- **PhishTank** - Community-driven phishing database
- **URLhaus** - Malware URL database
- **MaxMind** - GeoLite2 geographic databases
- **OASIS** - STIX 2.1 standard

---

**Ready to detect and analyze phishing threats!**
