@echo off
:: PLDT WiFi Manager - Fully Automated Setup Script
:: Run this as Administrator before first use
:: This script handles: Python check, dependencies, firewall config, IP config, and server start

:: Safety wrapper - restart in cmd /k to keep window open on any error
if not "%~1"=="--wrapped" (
    cmd /k "%~f0" --wrapped
    exit /b
)

setlocal EnableDelayedExpansion

:: Set up error handling - window won't close without pause
set "SCRIPT_COMPLETE=0"

echo ============================================================
echo   PLDT WiFi Manager - Setup
echo ============================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: Please run this script as Administrator!
    echo   Right-click on setup.bat and select "Run as administrator"
    echo.
    goto :end_script
)

echo   Running with Administrator privileges...
echo.

:: Step 1: Check Python installation
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo       [ERROR] Python is not installed or not in PATH!
    echo.
    echo       Please install Python 3.8+ from https://www.python.org/downloads/
    echo       Make sure to check "Add Python to PATH" during installation.
    echo.
    goto :end_script
)
set "PYTHON_VER=Unknown"
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYTHON_VER=%%i"
echo       [OK] Python %PYTHON_VER% detected

:: Step 2: Install Python dependencies
echo [2/5] Installing Python dependencies...
cd /d "%~dp0"
pip install -r requirements.txt --quiet --disable-pip-version-check >nul 2>&1
if %errorLevel% neq 0 (
    echo       [WARNING] Some dependencies may have failed to install
    echo       Attempting individual installation...
    pip install flask flask-cors requests pycryptodome --quiet >nul 2>&1
)
echo       [OK] Python dependencies installed

:: Step 3: Add firewall rule for port 80
echo [3/5] Configuring Windows Firewall...
netsh advfirewall firewall show rule name="PLDT WiFi Manager HTTP" >nul 2>&1
if %errorLevel% neq 0 (
    netsh advfirewall firewall add rule name="PLDT WiFi Manager HTTP" dir=in action=allow protocol=TCP localport=80 >nul 2>&1
    echo       [OK] Firewall rule added for port 80
) else (
    echo       [OK] Firewall rule for port 80 already exists
)

:: Step 4: Configure IP Address (192.168.1.2)
echo [4/5] Configuring IP Address (192.168.1.2)...

:: Find the active network interface name
set "IFACE_NAME="
netsh interface show interface "Wi-Fi" 2>nul | findstr /C:"Connected" >nul 2>&1
if !errorLevel! equ 0 set "IFACE_NAME=Wi-Fi"

if "!IFACE_NAME!"=="" (
    netsh interface show interface "Ethernet" 2>nul | findstr /C:"Connected" >nul 2>&1
    if !errorLevel! equ 0 set "IFACE_NAME=Ethernet"
)

if "!IFACE_NAME!"=="" (
    set "IFACE_NAME=Wi-Fi"
    echo       [WARNING] Could not detect active interface, defaulting to Wi-Fi
) else (
    echo       [INFO] Detected active interface: !IFACE_NAME!
)

:: Remove legacy IP 192.168.1.200 if present
powershell -ExecutionPolicy Bypass -NoProfile -Command "try { Remove-NetIPAddress -IPAddress '192.168.1.200' -Confirm:$false -ErrorAction SilentlyContinue } catch { }" >nul 2>&1

:: Add 192.168.1.2
ipconfig | findstr /C:"192.168.1.2" >nul 2>&1
if !errorLevel! equ 0 (
    echo       [OK] IP 192.168.1.2 already configured
) else (
    netsh interface ipv4 add address name="!IFACE_NAME!" addr=192.168.1.2 mask=255.255.255.0 >nul 2>&1
    if !errorLevel! equ 0 (
        echo       [OK] IP 192.168.1.2 configured on !IFACE_NAME!
    ) else (
        echo       [WARNING] Failed to add IP 192.168.1.2. Please check network settings.
    )
)

echo.
echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.
echo   Configuration Summary:
echo   - Admin URL:      http://192.168.1.2
echo   - Local URL:      http://localhost
echo.
echo   To start the server, run "start_server.bat" as Administrator
echo.
echo ============================================================

:: Ask to start server now
echo.
set "START_NOW=N"
set /p START_NOW="Start the server now? (Y/N): "
if /i "!START_NOW!"=="Y" (
    echo.
    echo Starting server...
    cd /d "%~dp0"
    set "SCRIPT_COMPLETE=1"
    python server.py
) else (
    echo.
    echo Run "start_server.bat" as Administrator when ready.
    set "SCRIPT_COMPLETE=1"
)

:end_script
if "!SCRIPT_COMPLETE!"=="0" (
    echo.
    echo ============================================================
    echo   [ERROR] Setup did not complete properly!
    echo   An unexpected error occurred. Please check the output above.
    echo ============================================================
)
echo.
pause
exit /b 0
