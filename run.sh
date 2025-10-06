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
echo "Starting Email Screening Prototype..."
echo "Server running at: http://127.0.0.1:${PORT}"
echo "Press Ctrl+C to stop."

uvicorn "$APP_MODULE" --reload --host "$HOST" --port "$PORT"

