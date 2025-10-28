@echo off
REM Traffic Viewer Launcher - Windows
REM ==================================
REM Quick launcher for HTTP/HTTPS Traffic Viewer

title HTTP/HTTPS Traffic Viewer Launcher

echo.
echo ========================================================
echo    HTTP/HTTPS Traffic Viewer - All-in-One Launcher
echo ========================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found
    echo Please install Python 3.6 or higher
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Check if script exists
if not exist "traffic_viewer_all_in_one.py" (
    echo ERROR: traffic_viewer_all_in_one.py not found
    echo Please run this script from the correct directory
    pause
    exit /b 1
)

:menu
echo Select launch mode:
echo   1. Simple GUI (recommended)
echo   2. Proxy only (no GUI)
echo   3. Custom port
echo   4. Exit
echo.
set /p choice="Enter choice [1-4]: "

if "%choice%"=="1" goto simple
if "%choice%"=="2" goto proxy
if "%choice%"=="3" goto custom
if "%choice%"=="4" goto end
echo Invalid choice
echo.
goto menu

:simple
echo.
echo Launching Simple GUI...
echo.
python traffic_viewer_all_in_one.py --gui simple
goto end

:proxy
echo.
echo Launching Proxy Only...
echo Press Ctrl+C to stop
echo.
python traffic_viewer_all_in_one.py --no-gui
goto end

:custom
echo.
set /p port="Enter port number [9000]: "
if "%port%"=="" set port=9000
echo.
echo Launching on port %port%...
echo.
python traffic_viewer_all_in_one.py --port %port%
goto end

:end
pause
