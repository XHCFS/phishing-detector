#!/usr/bin/env bash
#
# Launch the Streamlit threat intelligence dashboard
#

set -e

echo "🛡️  Starting Threat Intelligence Dashboard..."
echo ""

# Check if database exists
if [ ! -f "app/database/threat_feeds.db" ]; then
    echo "❌ Database not found: app/database/threat_feeds.db"
    echo ""
    echo "Please run the enrichment pipeline first:"
    echo "  1. python -m app.database.db     # Create schema"
    echo "  2. python -m app.database.enrich # Populate data"
    echo ""
    exit 1
fi

# Launch Streamlit
streamlit run app/dashboard/frontend.py \
    --server.port 8501 \
    --server.address localhost \
    --browser.gatherUsageStats false

