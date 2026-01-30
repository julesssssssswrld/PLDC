@echo off
:: PLDT WiFi Manager - Uninstall/Cleanup Script
:: Removes configurations added by setup.bat (Firewall rules, legacy IPs)

setlocal EnableDelayedExpansion

:: Change to script directory first
cd /d "%~dp0"

echo ============================================================
echo   PLDT WiFi Manager - Uninstall / Cleanup
echo ============================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   ERROR: Please run this script as Administrator!
    echo   Right-click on uninstall.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo   Running with Administrator privileges...
echo.
echo   This will remove:
echo   - Firewall rules for ports 80 and 5000
echo   - Legacy IP addresses (if present)
echo.
set /p CONFIRM="Are you sure you want to continue? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo.
    echo   Cancelled.
    pause
    exit /b 0
)
echo.

:: Step 1: Remove firewall rules
echo [1/2] Removing firewall rules...
netsh advfirewall firewall delete rule name="PLDT WiFi Manager HTTP" >nul 2>&1
netsh advfirewall firewall delete rule name="PLDT WiFi Manager Fallback" >nul 2>&1
netsh advfirewall firewall delete rule name="PLDT WiFi Manager" >nul 2>&1
echo       [OK] Firewall rules removed

:: Step 2: Remove legacy IP addresses (best effort)
echo [2/2] Removing legacy IP addresses...
powershell -ExecutionPolicy Bypass -NoProfile -Command "try { Remove-NetIPAddress -IPAddress '192.168.1.2' -Confirm:$false -ErrorAction SilentlyContinue; Write-Host '      [OK] Removed IP 192.168.1.2' } catch { }"
powershell -ExecutionPolicy Bypass -NoProfile -Command "try { Remove-NetIPAddress -IPAddress '192.168.1.200' -Confirm:$false -ErrorAction SilentlyContinue; Write-Host '      [OK] Removed IP 192.168.1.200' } catch { }"

echo.
echo ============================================================
echo   Cleanup Complete!
echo ============================================================
echo.
pause
