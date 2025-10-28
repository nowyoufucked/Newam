@echo off
REM Windows Port Troubleshooting Script
REM Checks what's using port 8888 and suggests solutions

echo ========================================
echo HTTP/HTTPS Viewer - Port Troubleshooter
echo ========================================
echo.

echo Checking if port 8888 is in use...
netstat -ano | findstr :8888
echo.

echo ========================================
echo If you see output above, port 8888 is already in use.
echo.
echo Solutions:
echo 1. Use a different port (try 8080, 8889, 9000)
echo    Example: python3 http_https_viewer.py -p 9000
echo.
echo 2. Kill the process using the port
echo    Find the PID (last column above) and run:
echo    taskkill /PID [PID_NUMBER] /F
echo.
echo 3. Run as Administrator (right-click, Run as Administrator)
echo.
echo 4. Allow through Windows Firewall:
echo    - Open Windows Defender Firewall
echo    - Allow an app through firewall
echo    - Add Python to allowed apps
echo.
echo ========================================
pause
