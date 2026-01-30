@echo off
:: PLDT WiFi Manager - Start Server
:: Run this as Administrator
setlocal EnableDelayedExpansion

echo ============================================================
echo   PLDT WiFi Manager - Starting Server
echo ============================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: Please run this script as Administrator!
    echo   Right-click on start_server.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo   Running with Administrator privileges...
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: Python is not installed!
    echo   Please run setup.bat first.
    pause
    exit /b 1
)

cd /d "%~dp0"

:: Quick dependency check - install if missing
pip show flask >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing required dependencies...
    pip install -r requirements.txt --quiet --disable-pip-version-check >nul 2>&1
)

echo   Server starting on:
echo.
echo   ADMIN PANEL:    http://192.168.1.200
echo   LOCAL ACCESS:   http://localhost
echo.
echo   Press Ctrl+C to stop the server
echo ============================================================
echo.

python server.py

pause
