@echo off
echo ===================================================
echo   CyGPT Automated Setup and Fix Utility (Windows)
echo ===================================================
echo.
echo [1] Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH! Please install Python 3.10+ and try again.
    pause
    exit /b
)
echo Python found.
echo.

echo [2] Setting up Python Virtual Environment (venv)...
if not exist "venv\" (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)
echo.

echo [3] Activating Virtual Environment and installing dependencies...
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo Dependencies installed successfully!
echo.

echo [4] Running Database Migrations...
python manage.py makemigrations
python manage.py migrate
echo Database is up to date!
echo.

echo [5] Collecting Static Files...
python manage.py collectstatic --noinput
echo Static files collected!
echo.

echo ===================================================
echo   Setup Complete! CyGPT is ready to run.
echo ===================================================
echo To start the server, run:
echo call venv\Scripts\activate
echo python manage.py runserver
echo.
pause
