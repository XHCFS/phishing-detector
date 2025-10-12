#!/usr/bin/env fish

set VENV_DIR ".venv"
set VENV_PYTHON "$VENV_DIR/bin/python"

if not test -d $VENV_DIR
    echo "❌ Virtual environment not found. Run: python run.py setup"
    exit 1
end

if not test -f $VENV_PYTHON
    echo "❌ Python not found in venv. Run: python run.py setup"
    exit 1
end

set TOKEN_PATH "app/detector/token.json"
if not test -f $TOKEN_PATH
    echo "⚠️  Gmail OAuth token not found."
    echo "   Run: python run.py auth"
    echo ""
end

$VENV_PYTHON -c "
import sqlite3
from pathlib import Path
print('📊 Threat Database Status:')
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
        print(f'   OpenPhish: {openphish:,} URLs')
        print(f'   PhishTank: {phishtank:,} URLs')
        print(f'   URLhaus: {urlhaus:,} URLs')
        print(f'   Total: {openphish+phishtank+urlhaus:,} threat URLs')
    else:
        print('   ⚠️ Database not found. Run: python run.py setup')
except Exception as e:
    print(f'   ⚠️ Could not read database: {e}')
" 2>/dev/null; or echo "   ⚠️ Database check failed"

echo ""
echo "🚀 Starting FastAPI server..."
echo "   URL: http://127.0.0.1:8000"
echo "   Press Ctrl+C to stop"
echo ""

$VENV_PYTHON -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
