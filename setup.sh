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

# Optional database initialization
source .venv/bin/activate 
if python3 -c "from app.database.db import init_db; init_db()" 2>/dev/null; then
    echo "Database initialized successfully."
else
    echo "Database initialization skipped (db.py missing or failed)."
fi

echo "Setup complete."
echo "To run the application, execute:"
echo "./run.sh"

