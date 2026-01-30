@echo off
:: PLDT WiFi Manager - Uninstall/Cleanup Script
:: Removes: Scheduled Task, Firewall rules, IPs, libs, and logs

:: Safety wrapper - keeps window open
if not "%~1"=="--wrapped" (
    cmd /k "%~f0" --wrapped
    exit /b
)

setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "TASK_NAME=PLDTWiFiManager"

echo ============================================================
echo   PLDT WiFi Manager - Uninstall / Cleanup
echo ============================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: Please run this script as Administrator!
    exit /b 1
)

echo   Running cleanup...
echo.

:: Step 1: Kill Python and remove scheduled task
echo [1/4] Stopping server and removing scheduled task...
taskkill /f /im python.exe >nul 2>&1
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
echo       [OK] Done

:: Step 2: Remove NSSM service if exists (legacy cleanup)
echo [2/4] Cleaning up legacy NSSM service...
sc query %TASK_NAME% >nul 2>&1
if !errorLevel! equ 0 (
    if exist "%~dp0nssm\nssm.exe" (
        "%~dp0nssm\nssm.exe" stop %TASK_NAME% >nul 2>&1
        timeout /t 1 /nobreak >nul
        "%~dp0nssm\nssm.exe" remove %TASK_NAME% confirm >nul 2>&1
    ) else (
        sc stop %TASK_NAME% >nul 2>&1
        sc delete %TASK_NAME% >nul 2>&1
    )
)
if exist "%~dp0nssm" rmdir /s /q "%~dp0nssm" >nul 2>&1
echo       [OK] Done

:: Step 3: Remove firewall, logs, libs
echo [3/4] Removing firewall rules and files...
netsh advfirewall firewall delete rule name="PLDT WiFi Manager HTTP" >nul 2>&1
if exist "%~dp0logs" rmdir /s /q "%~dp0logs" >nul 2>&1
if exist "%~dp0libs" rmdir /s /q "%~dp0libs" >nul 2>&1
if exist "%~dp0start_service.cmd" del /f "%~dp0start_service.cmd" >nul 2>&1
echo       [OK] Done

:: Step 4: Reset network to DHCP
echo [4/4] Resetting network to DHCP...
set "IFACE_NAME=Wi-Fi"
netsh interface show interface "Wi-Fi" 2>nul | findstr /C:"Connected" >nul 2>&1
if !errorLevel! neq 0 (
    netsh interface show interface "Ethernet" 2>nul | findstr /C:"Connected" >nul 2>&1
    if !errorLevel! equ 0 set "IFACE_NAME=Ethernet"
)
powershell -NoProfile -Command "Remove-NetIPAddress -IPAddress '192.168.1.200' -Confirm:$false -ErrorAction SilentlyContinue" >nul 2>&1
netsh interface ipv4 set address name="!IFACE_NAME!" source=dhcp >nul 2>&1
netsh interface ipv4 set dns name="!IFACE_NAME!" source=dhcp >nul 2>&1
echo       [OK] Done

echo.
echo ============================================================
echo   Uninstall Complete!
echo ============================================================
echo.
exit /b
