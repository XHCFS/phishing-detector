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
./setup.sh
```

Start the application:

```bash
./run.sh
```

The setup script will:
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
./run.sh
```

Access the dashboard at: http://localhost:8000

### Update Threat Feeds
```bash
# Update raw threat feeds
python -m app.database.grabrawdata

# Enrich new URLs (process 1000 at a time)
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
├── setup.sh                # Automated setup script
├── run.sh                  # Start application
└── requirements.txt        # Python dependencies
```

---

## Documentation

- [Database Setup Guide](app/database/README.md) - Quick start and commands
- [Complete Database Documentation](app/database/Documentation%20%26%20Sources%20Research/DATABASE_GUIDE.md) - Technical details (985 lines)
- [Data Sources](app/database/Documentation%20%26%20Sources%20Research/Data%20Sources.md) - Threat feed specifications

---

## Troubleshooting

### Setup Issues

**"Virtual environment not found"**
```bash
./setup.sh
```

**"Database initialization failed"**
```bash
python -m app.database.rawdb
python -m app.database.grabrawdata
python -m app.database.db
```

**"No threat data"**
```bash
# Ensure you have internet connection, then:
python -m app.database.grabrawdata
```

### More Help

See [Database README](app/database/README.md) for database-specific troubleshooting.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

See [LICENSE](LICENSE) file for details.
