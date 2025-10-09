#!/usr/bin/env bash
set -e  # stop if any command fails

VENV_DIR=".venv"
APP_MODULE="app.main:app"
HOST="0.0.0.0"
PORT=8000

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

# Detect OS and choose correct activate script
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    ACTIVATE="$VENV_DIR/Scripts/activate"
else
    ACTIVATE="$VENV_DIR/bin/activate"
fi

# Activate virtual environment
source "$ACTIVATE"

# Ensure uvicorn is installed
if ! python -c "import uvicorn" &> /dev/null; then
    echo "uvicorn not found in the virtual environment. Installing..."
    pip install uvicorn
fi

# Run the FastAPI app
echo "=========================================="
echo "  Phishing Detector Application"
echo "=========================================="
echo ""
echo "Starting server..."
echo "URL: http://127.0.0.1:${PORT}"
echo ""
echo "Threat Database Status:"
python -c "
import sqlite3
from pathlib import Path
try:
    db_path = Path('app/database/threat_feeds_raw.db')
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM openphish_feed')
        openphish = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM phishtank_archival')
        phishtank = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM urlhaus_api')
        urlhaus = cursor.fetchone()[0]
        conn.close()
        print(f'   - OpenPhish: {openphish:,} URLs')
        print(f'   - PhishTank: {phishtank:,} URLs')
        print(f'   - URLhaus: {urlhaus:,} URLs')
        print(f'   - Total: {openphish+phishtank+urlhaus:,} threat URLs')
    else:
        print('   WARNING: Raw database not found. Run ./setup.sh')
except Exception as e:
    print(f'   WARNING: Could not read database')
" 2>/dev/null || echo "   WARNING: Database not initialized"

echo ""
echo "Documentation: app/database/README.md"
echo "Press Ctrl+C to stop"
echo ""

uvicorn "$APP_MODULE" --reload --host "$HOST" --port "$PORT"

