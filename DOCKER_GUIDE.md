# Docker Guide for Phishing Detector

## Quick Start

### 1. Build the Image
```bash
docker build -t python_zinad .
```

### 2. Run with Database Persistence (Recommended)
```bash
# Interactive mode - databases saved to host
docker run -it --rm \
  -v $(pwd)/app/database:/app/app/database \
  -p 8501:8501 \
  -p 8000:8000 \
  python_zinad bash
```

**Inside the container, run:**
```bash
# Setup database (saves to host machine)
python3 run.py setup --fast

# Authenticate Gmail
python3 run.py auth

# Run dashboard
python3 run.py dashboard --host 0.0.0.0
```

**Access dashboard:** `http://localhost:8501`

### 3. Or Use the Helper Script (Fish Shell)
```bash
./docker_helper.fish build      # Build image
./docker_helper.fish run        # Run interactive container
./docker_helper.fish dashboard  # Run dashboard directly
```

## Important: Database Persistence

**Always use `-v $(pwd)/app/database:/app/app/database`** to mount the database directory. This ensures:
- ✅ Databases are created on your host machine
- ✅ Data persists after container stops
- ✅ You can access databases outside Docker

**Without the volume mount:**
- ❌ Databases are created inside the container
- ❌ All data is lost when container stops

## Common Commands

```bash
# Setup database (with persistence)
docker run --rm \
  -v $(pwd)/app/database:/app/app/database \
  python_zinad python3 run.py setup --fast

# Run dashboard (with persistence)
docker run -it --rm \
  -v $(pwd)/app/database:/app/app/database \
  -p 8501:8501 \
  python_zinad python3 run.py dashboard --host 0.0.0.0

# Interactive shell (with persistence)
docker run -it --rm \
  -v $(pwd)/app/database:/app/app/database \
  -p 8501:8501 \
  python_zinad bash
```

## What Was Fixed

The original error **"❌ Python interpreter not found in virtual environment"** occurred because:
- `run.py` looked for a `.venv` directory (excluded from Docker by `.dockerignore`)
- Virtual environments aren't needed in Docker (Docker provides isolation)

**Solution:** Modified `run.py` to detect Docker environment and use system Python directly.

## Ports

- `8501` - Streamlit Dashboard
- `8000` - FastAPI Server

Map them with `-p HOST:CONTAINER`:
```bash
-p 8501:8501  # Dashboard on localhost:8501
-p 8000:8000  # API on localhost:8000
```

## Troubleshooting

**Database not found after restart**
- Always use the volume mount: `-v $(pwd)/app/database:/app/app/database`

**Port already in use**
- Change host port: `-p 8502:8501` (access via localhost:8502)

**Cannot access dashboard**
- Use `--host 0.0.0.0` inside container
- Check port mapping with `-p 8501:8501`
- Access via `http://localhost:8501` on host browser
