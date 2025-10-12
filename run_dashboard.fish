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

if not test -f "app/database/threat_feeds.db"
    echo "❌ Enriched database not found."
    echo "   Run: python run.py enrich"
    exit 1
end

echo "📊 Starting Threat Intelligence Dashboard..."
echo "   URL: http://localhost:8501"
echo "   Press Ctrl+C to stop"
echo ""

$VENV_PYTHON -m streamlit run app/dashboard/frontend.py \
    --server.port 8501 \
    --server.address localhost \
    --browser.gatherUsageStats false
