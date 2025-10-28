@echo off
REM HTTP/HTTPS Traffic Viewer GUI Launcher for Windows

echo Starting HTTP/HTTPS Traffic Viewer GUI...
echo ==========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Launch GUI
cd /d "%~dp0"
python gui.py

pause
