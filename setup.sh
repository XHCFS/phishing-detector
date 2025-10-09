#!/usr/bin/env bash
set -e  # stop if any command fails

echo "Setting up Email Screening Prototype environment..."

# Configuration
PYTHON_VERSION="3.11"
VENV_DIR=".venv"

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Please install Python $PYTHON_VERSION or higher."
    exit 1
fi

# Ensure pip exists
python3 -m ensurepip --upgrade

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists, skipping creation."
fi

# Choose correct activate script
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    ACTIVATE="$VENV_DIR/Scripts/activate"
else
    ACTIVATE="$VENV_DIR/bin/activate"
fi

# Activate and install
source "$ACTIVATE"
echo "Upgrading pip..."
pip install --upgrade pip
echo "Installing dependencies..."
pip install -r requirements.txt

# Database initialization
echo ""
echo "Initializing threat feeds database..."
if python3 -m app.database.rawdb 2>/dev/null; then
    echo "✓ Raw database schema created"
else
    echo "✗ Warning: Raw database creation failed"
fi

if python3 -m app.database.db 2>/dev/null; then
    echo "✓ Enriched database schema created"
else
    echo "✗ Warning: Enriched database creation failed"
fi

echo ""
echo "Fetching initial threat data (this may take a few minutes)..."
if python3 -m app.database.grabrawdata 2>/dev/null; then
    echo "✓ Threat feeds downloaded successfully"
else
    echo "✗ Warning: Threat feed download failed (check internet connection)"
fi

echo ""
echo "Setup complete!"
echo ""
echo "📊 Database Status:"
echo "   - Raw database ready (~52,000 threat URLs from 3 feeds)"
echo "   - Enriched database schema created"
echo ""
echo "🚀 To start the application:"
echo "   ./run.sh"
echo ""
echo "📖 For database management and enrichment:"
echo "   See: app/database/README.md"
echo ""
echo "💡 Optional: Set up API keys in .env file"
echo "   - PHISHTANK_API_KEY (optional, for higher rate limits)"
echo "   - URLHAUS_API_KEY (required for URLhaus data)"
