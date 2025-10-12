#!/usr/bin/env fish

set VENV_DIR ".venv"
set VENV_PYTHON "$VENV_DIR/bin/python"

echo "🔧 Setting up phishing detector environment..."
echo ""

if not command -v python3 &> /dev/null
    echo "❌ Python3 not found. Please install Python 3.11+"
    exit 1
end

python3 -m ensurepip --upgrade 2>/dev/null; or true

if not test -d $VENV_DIR
    echo "📦 Creating virtual environment..."
    python3 -m venv $VENV_DIR
else
    echo "✓ Virtual environment exists"
end

echo "📦 Installing dependencies..."
$VENV_PYTHON -m pip install --upgrade pip -q
$VENV_PYTHON -m pip install -r requirements.txt -q

echo ""
echo "🗄️  Initializing databases..."
$VENV_PYTHON -m app.database.rawdb
$VENV_PYTHON -m app.database.db
$VENV_PYTHON -m app.detector.core --setup-db

set DETECTOR_CRED_DIR "app/detector"
set DETECTOR_CRED_EXAMPLE "$DETECTOR_CRED_DIR/credentials.json.example"
set DETECTOR_CRED "$DETECTOR_CRED_DIR/credentials.json"

if test -f $DETECTOR_CRED_EXAMPLE; and not test -f $DETECTOR_CRED
    echo "📝 Copying credentials example..."
    cp $DETECTOR_CRED_EXAMPLE $DETECTOR_CRED
end

echo ""
echo "🌐 Fetching threat feeds (may take a few minutes)..."
$VENV_PYTHON -m app.database.grabrawdata

echo ""
echo "🔍 Enriching data (limit: 1000 URLs)..."
$VENV_PYTHON -m app.database.enrich --limit=1000

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  • Authenticate Gmail:  python run.py auth"
echo "  • Run API server:      python run.py api"
echo "  • Run dashboard:       python run.py dashboard"
echo ""
echo "Or use the new centralized runner:"
echo "  python run.py --help"
