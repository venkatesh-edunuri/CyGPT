#!/bin/bash
echo "==================================================="
echo "  CyGPT Automated Setup and Fix Utility (Mac/Linux)"
echo "==================================================="
echo ""

echo "[1] Checking for Python installation..."
if ! command -v python3 &> /dev/null
then
    echo "Python3 is not installed or not in PATH! Please install Python 3.10+ and try again."
    exit 1
fi
echo "Python found."
echo ""

echo "[2] Setting up Python Virtual Environment (venv)..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi
echo ""

echo "[3] Activating Virtual Environment and installing dependencies..."
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo "Dependencies installed successfully!"
echo ""

echo "[4] Running Database Migrations..."
python manage.py makemigrations
python manage.py migrate
echo "Database is up to date!"
echo ""

echo "[5] Collecting Static Files..."
python manage.py collectstatic --noinput
echo "Static files collected!"
echo ""

echo "==================================================="
echo "  Setup Complete! CyGPT is ready to run."
echo "==================================================="
echo "To start the server, run:"
echo "source venv/bin/activate"
echo "python manage.py runserver"
echo ""
