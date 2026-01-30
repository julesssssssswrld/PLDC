@echo off
:: PLDT WiFi Manager - Setup using Task Scheduler (more reliable than NSSM)
:: Handles: Python, dependencies, firewall, IP, scheduled task installation

if not "%~1"=="--wrapped" (
    cmd /k "%~f0" --wrapped
    exit /b
)

setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "TASK_NAME=PLDTWiFiManager"
set "LOGS_DIR=%SCRIPT_DIR%logs"

echo ============================================================
echo   PLDT WiFi Manager - Setup
echo ============================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   [ERROR] Please run this script as Administrator!
    goto :end_script
)
echo   [OK] Running with Administrator privileges
echo.

:: Step 1: Check Python installation
echo   [1/6] Checking Python installation...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo         [ERROR] Python is not installed or not in PATH!
    goto :end_script
)
for /f "delims=" %%i in ('where python') do (
    set "PYTHON_PATH=%%i"
    goto :got_python
)
:got_python
echo         [OK] Python found: %PYTHON_PATH%

:: Step 2: Install Python dependencies to local libs folder
echo   [2/6] Installing Python dependencies...
set "LIBS_DIR=%SCRIPT_DIR%libs"
if not exist "%LIBS_DIR%" mkdir "%LIBS_DIR%" >nul 2>&1
pip install flask flask-cors requests pycryptodome --target "%LIBS_DIR%" --quiet --upgrade >nul 2>&1
echo         [OK] Dependencies installed

:: Step 3: Configure firewall
echo   [3/6] Configuring Windows Firewall...
netsh advfirewall firewall show rule name="PLDT WiFi Manager HTTP" >nul 2>&1
if %errorLevel% neq 0 (
    netsh advfirewall firewall add rule name="PLDT WiFi Manager HTTP" dir=in action=allow protocol=TCP localport=80 >nul 2>&1
)
echo         [OK] Firewall configured

:: Step 4: Configure IP Address
echo   [4/6] Configuring IP Address (192.168.1.200)...
set "IFACE_NAME=Wi-Fi"
netsh interface show interface "Wi-Fi" 2>nul | findstr /C:"Connected" >nul 2>&1
if !errorLevel! neq 0 (
    netsh interface show interface "Ethernet" 2>nul | findstr /C:"Connected" >nul 2>&1
    if !errorLevel! equ 0 set "IFACE_NAME=Ethernet"
)
netsh interface ipv4 set address name="!IFACE_NAME!" static 192.168.1.200 255.255.255.0 192.168.1.1 >nul 2>&1
netsh interface ipv4 set dns name="!IFACE_NAME!" static 1.1.1.1 primary >nul 2>&1
netsh interface ipv4 add dns name="!IFACE_NAME!" 8.8.8.8 index=2 >nul 2>&1
echo         [OK] IP configured on !IFACE_NAME!

:: Step 5: Create logs directory
echo   [5/6] Creating logs directory...
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%" >nul 2>&1
echo         [OK] Logs directory ready

:: Step 6: Create scheduled task (runs at startup, as SYSTEM, with highest privileges)
echo   [6/6] Creating scheduled task...

:: Remove existing task if present
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: Create startup batch script (Python handles its own logging now)
echo @echo off > "%SCRIPT_DIR%start_service.cmd"
echo cd /d "%SCRIPT_DIR%" >> "%SCRIPT_DIR%start_service.cmd"
echo set "PYTHONPATH=%LIBS_DIR%;%%PYTHONPATH%%" >> "%SCRIPT_DIR%start_service.cmd"
echo :loop >> "%SCRIPT_DIR%start_service.cmd"
echo "%PYTHON_PATH%" "%SCRIPT_DIR%server.py" >> "%SCRIPT_DIR%start_service.cmd"
echo timeout /t 5 /nobreak ^>nul >> "%SCRIPT_DIR%start_service.cmd"
echo goto loop >> "%SCRIPT_DIR%start_service.cmd"

:: Create the scheduled task - runs at system startup
schtasks /create /tn "%TASK_NAME%" /tr "\"%SCRIPT_DIR%start_service.cmd\"" /sc onstart /ru SYSTEM /rl HIGHEST /f >nul 2>&1
if !errorLevel! neq 0 (
    echo         [ERROR] Failed to create scheduled task
    goto :end_script
)
echo         [OK] Scheduled task created

:: Start the task now
echo.
echo   Starting server...
schtasks /run /tn "%TASK_NAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

:: Check if running
tasklist /fi "imagename eq python.exe" 2>nul | findstr /i "python" >nul 2>&1
if !errorLevel! equ 0 (
    echo   [OK] Server is running!
) else (
    echo   [WARNING] Server may not have started. Check %LOGS_DIR%\server.log
)

echo.
echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.
echo   Access: http://192.168.1.200
echo   Logs:   %LOGS_DIR%\server.log
echo.
echo   Manage:
echo     Stop:    taskkill /f /im python.exe
echo     Start:   schtasks /run /tn %TASK_NAME%
echo     Remove:  schtasks /delete /tn %TASK_NAME% /f
echo ============================================================

:end_script
echo.
exit /b
