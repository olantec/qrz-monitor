@echo off
REM Installs QRZ Monitor dependencies for Windows

echo Checking for Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed!
    echo Please download and install Python 3.12+ from https://www.python.org/downloads/windows/
    echo After installation, re-run this script.
    pause
    exit /b
)

echo Upgrading pip...
python -m ensurepip --default-pip >nul 2>&1
python -m pip install --upgrade pip

echo Installing required dependencies: requests, pystray, Pillow
python -m pip install requests pystray Pillow

echo All dependencies installed successfully!
pause
