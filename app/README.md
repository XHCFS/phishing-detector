# Phishing Detector - Main Application Module

Central orchestration module that integrates all components (database, detector, dashboard) into a unified FastAPI application.

## Overview

The **app module** serves as the entry point and coordinator for the entire phishing detection system. It provides:

- **FastAPI Application** - RESTful API server
- **Module Integration** - Combines database, detector, and dashboard modules
- **Unified Scoring** - Centralized risk scoring logic
- **API Routing** - Routes requests to appropriate submodules

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     APP MODULE                           │
│                  (FastAPI Application)                   │
└─────────────────────────────────────────────────────────┘

         main.py (FastAPI app)
              │
              ├──→ /dashboard (Dashboard Router)
              │    └── app.dashboard.routes
              │        └── Streamlit interface
              │
              ├──→ /detector (Detector Router)
              │    └── app.detector.api
              │        └── Email analysis
              │
              └──→ / (Root endpoint)
                   └── Status check

         scoring.py (Shared scoring logic)
              │
              ├── calculate_risk_score()
              ├── get_risk_level()
              └── get_score_breakdown()
              │
              └── Used by:
                  ├── app.detector.core
                  └── app.detector.scoring (duplicate)
```

---

## Components

### 1. `main.py` (20 lines)

**Purpose:** FastAPI application entry point

```python
from fastapi import FastAPI
from app.dashboard.routes import router as dashboard_router
from app.detector.api import router as detector_router

app = FastAPI(title="Phishing Detector")

# Register module routers
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(detector_router, prefix="/detector", tags=["Detector"])

@app.get("/")
def home():
    return {
        "status": "running",
        "message": "Welcome to the Phishing Detector!"
    }
```

**Features:**
- Registers submodule routers with prefixes
- Provides root endpoint for health check
- Auto-generated API docs at `/docs`

---

### 2. `scoring.py` (200 lines)

**Purpose:** Risk scoring algorithm shared across modules

See [Risk Scoring Documentation](detector/README.md#risk-scoring) for complete details.

**Key Functions:**

```python
def calculate_risk_score(
    url: str,
    http_status_code: Optional[int] = None,
    online_status: Optional[str] = None,
    last_seen: Optional[str] = None,
    creation_date: Optional[str] = None,
    tld: Optional[str] = None
) -> int:
    """
    Calculate risk score (0-100) based on 5 components.
    
    Returns: Total risk score
    """
    pass

def get_risk_level(score: int) -> str:
    """
    Convert numeric score to risk level.
    
    Returns: "Critical", "High", "Medium", or "Low"
    """
    pass

def get_score_breakdown(url, ...) -> dict:
    """
    Get detailed component scores.
    
    Returns: Dictionary with individual scores and total
    """
    pass
```

**Risk Components:**
- **Liveness (0-35):** HTTP status and online status
- **Recency (0-25):** Days since last seen
- **Domain Age (0-20):** Days since creation
- **TLD/Platform (0-10):** Suspicious TLDs and platforms
- **Keywords (0-10):** Suspicious keywords in URL

**Risk Levels:**
```python
85-100 → Critical 🚨
70-84  → High     ⚠️
50-69  → Medium   ⚡
0-49   → Low      ✓
```

---

## API Endpoints

**Base URL:** `http://localhost:8000`

### Root Endpoints

#### `GET /`
Application health check.

**Response:**
```json
{
  "status": "running",
  "message": "Welcome to the Phishing Detector!"
}
```

**Usage:**
```bash
curl http://localhost:8000/
```

---

### Dashboard Endpoints

**Prefix:** `/dashboard`

#### `GET /dashboard/`
Renders dashboard home page (HTML template).

**See:** [Dashboard Documentation](dashboard/README.md)

---

### Detector Endpoints

**Prefix:** `/detector`

#### `GET /detector/check?email_id={id}`
Analyze a specific email.

**Parameters:**
- `email_id` (required): Email message ID

**Response:**
```json
{
  "email_id": "msg123",
  "result": "Scanned msg123: enriched 3 URLs"
}
```

**See:** [Detector Documentation](detector/README.md)

---

## Running the Application

### Method 1: Using Centralized Runner (Recommended)
```bash
# Start API server
python run.py api

# With auto-reload for development
python run.py api --reload

# Custom host and port
python run.py api --host 127.0.0.1 --port 8080

# Start dashboard
python run.py dashboard
```

### Method 2: Using Shell Scripts
```bash
# Bash
./run.sh                # API server
./run_dashboard.sh      # Dashboard

# Fish shell
./run.fish              # API server
./run_dashboard.fish    # Dashboard
```

### Method 3: Direct uvicorn Command
```bash
# Development mode (auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Method 4: From Python
```python
import uvicorn
uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
```

---

## API Documentation

### Interactive API Docs

**Swagger UI:** `http://localhost:8000/docs`
- Interactive API testing
- Request/response schemas
- Try endpoints directly in browser

**ReDoc:** `http://localhost:8000/redoc`
- Alternative API documentation
- Clean, readable format

---

## Module Integration

### Database Module
- **Purpose:** Threat intelligence storage and enrichment
- **Integration:** Used by detector for URL enrichment
- **See:** [Database Documentation](database/README.md)

### Detector Module
- **Purpose:** Email analysis and risk scoring
- **Integration:** Exposed via `/detector` endpoints
- **See:** [Detector Documentation](detector/README.md)

### Dashboard Module
- **Purpose:** Web interface for data visualization
- **Integration:** Exposed via `/dashboard` endpoints
- **Note:** Streamlit runs separately on port 8501
- **See:** [Dashboard Documentation](dashboard/README.md)

---

## File Structure

```
app/
├── __init__.py               # Package initialization
├── main.py                   # FastAPI application (20 lines)
├── scoring.py                # Risk scoring algorithm (200 lines)
│
├── database/                 # Database module
│   ├── README.md             # Database documentation
│   ├── db.py                 # Schema creation
│   ├── rawdb.py              # Raw database schema
│   ├── grabrawdata.py        # Threat feed collector
│   ├── enrich.py             # Enrichment pipeline
│   └── Documentation/
│       └── DATABASE_GUIDE.md # Complete database docs
│
├── detector/                 # Detector module
│   ├── README.md             # Detector documentation
│   ├── core.py               # Email fetcher & URL processor
│   ├── api.py                # FastAPI routes
│   ├── scoring.py            # Risk scoring (duplicate)
│   └── Documentation/
│       └── DETECTOR_GUIDE.md # Complete detector docs
│
└── dashboard/                # Dashboard module
    ├── README.md             # Dashboard documentation
    ├── frontend.py           # Streamlit app
    ├── routes.py             # FastAPI routes
    ├── templates/
    │   └── index.html        # HTML template
    └── Documentation/
        └── DASHBOARD_GUIDE.md # Complete dashboard docs
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Gmail OAuth (for detector module)
# GMAIL_CREDENTIALS_PATH=/path/to/credentials.json

# Threat feed API keys (for database module)
PHISHTANK_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here

# Database path (optional)
# THREAT_FEEDS_DB_PATH=/path/to/threat_feeds.db
```

### Server Configuration

**Development:**
```bash
# Auto-reload on code changes
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Production:**
```bash
# Multiple workers for performance
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# With Gunicorn
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

---

## Usage Examples

### Python API Client

```python
import requests

# Health check
response = requests.get('http://localhost:8000/')
print(response.json())

# Analyze email
response = requests.get(
    'http://localhost:8000/detector/check',
    params={'email_id': 'msg123'}
)
print(response.json())
```

### Command Line (curl)

```bash
# Health check
curl http://localhost:8000/

# Analyze email
curl "http://localhost:8000/detector/check?email_id=msg123"

# View API docs
curl http://localhost:8000/docs
```

---

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run specific module tests
pytest tests/test_detector.py
pytest tests/test_database.py

# With coverage
pytest --cov=app tests/
```

### Code Quality

```bash
# Format code
black app/

# Lint code
flake8 app/

# Type checking
mypy app/
```

---

## Deployment

### Docker

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Build and run:**
```bash
# Build image
docker build -t phishing-detector .

# Run container
docker run -p 8000:8000 phishing-detector
```

### Docker Compose

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - PHISHTANK_API_KEY=${PHISHTANK_API_KEY}
      - URLHAUS_API_KEY=${URLHAUS_API_KEY}
    volumes:
      - ./app/database:/app/app/database
  
  dashboard:
    build: .
    command: streamlit run app/dashboard/frontend.py
    ports:
      - "8501:8501"
    volumes:
      - ./app/database:/app/app/database
```

---

## Troubleshooting

### Server Won't Start

**"Port already in use"**
```bash
# Check what's using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
uvicorn app.main:app --port 8001
```

**"Module not found"**
```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import fastapi; print(fastapi.__version__)"
```

### API Errors

**404 Not Found**
```
# Check route registration
# Visit http://localhost:8000/docs to see all routes

# Verify endpoint exists
curl -v http://localhost:8000/detector/check?email_id=test
```

**500 Internal Server Error**
```
# Check server logs
# Errors printed to console in --reload mode

# Enable debug mode (in main.py)
app = FastAPI(title="Phishing Detector", debug=True)
```

### Module Integration Issues

**"Database not found"**
```bash
# Initialize database
python -m app.database.db
python -m app.database.grabrawdata
```

**"Gmail authentication failed"**
```bash
# Setup OAuth
python -m app.detector.core --authenticate
```

---

## Dependencies

```bash
# Core
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-dotenv==1.0.0

# Database
requests==2.31.0
python-whois==0.8.0
geoip2==4.7.0
ipwhois==1.2.0
langdetect==1.0.9

# Detector
google-auth==2.23.3
google-auth-oauthlib==1.1.0
google-api-python-client==2.103.0
aiohttp==3.9.0

# Dashboard
streamlit==1.28.1
plotly==5.17.0
pandas==2.1.2
```

See `requirements.txt` for complete list.

---

## Summary

**Purpose:** Central orchestration and API layer

**Technology:** FastAPI + Uvicorn

**Components Integrated:**
- Database (threat intelligence)
- Detector (email analysis)
- Dashboard (visualization)

**Endpoints:**
- `/` - Health check
- `/detector/check` - Analyze email
- `/dashboard/` - Web interface
- `/docs` - API documentation

**Deployment:** Docker, uvicorn, or gunicorn

**Best Practices:**
- Run database initialization first
- Setup Gmail OAuth before using detector
- Use `--reload` for development
- Use multiple workers for production
- Monitor logs for errors

---

Ready to orchestrate phishing detection!
