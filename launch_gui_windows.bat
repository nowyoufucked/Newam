@echo off
REM Launch Enhanced GUI on Windows with automatic port detection
REM Tries multiple ports if default is blocked

echo ========================================
echo Enhanced HTTP/HTTPS Traffic Viewer
echo Starting GUI...
echo ========================================
echo.

REM Try port 9000 first (less likely to be blocked)
echo Trying port 9000...
python3 enhanced_gui.py --port 9000 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Port 9000 failed, trying 8080...
    python3 enhanced_gui.py --port 8080 2>nul
)
if %ERRORLEVEL% NEQ 0 (
    echo Port 8080 failed, trying 8889...
    python3 enhanced_gui.py --port 8889 2>nul
)
if %ERRORLEVEL% NEQ 0 (
    echo Port 8889 failed, trying 3128...
    python3 enhanced_gui.py --port 3128 2>nul
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo ERROR: Could not start proxy on any port!
    echo.
    echo Please try one of these solutions:
    echo 1. Run as Administrator (right-click this file, "Run as Administrator")
    echo 2. Manually specify a port in the GUI after it opens
    echo 3. Check Windows Firewall settings
    echo 4. Run check_port_windows.bat to see what's using the ports
    echo ========================================
    pause
)
