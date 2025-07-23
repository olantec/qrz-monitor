#!/bin/bash
# Installs QRZ Monitor dependencies for Linux (Debian, Ubuntu, Raspberry Pi)
# Usage:
#   bash install-linux.sh
#
# This script will:
#   - Update your package list
#   - Install Python3, pip and venv if needed
#   - Create and activate a virtual environment (.venv)
#   - Install all required Python dependencies in the venv

echo "=== QRZ Monitor Linux Installer ==="
echo "This script will install all dependencies for QRZ Monitor."
echo "If you see any errors, please check your internet connection and permissions."
echo "-----------------------------------"

echo "Updating package list..."
sudo apt update

echo "Installing Python3, pip and venv if needed..."
sudo apt install -y python3 python3-pip
echo "Checking Python3 installation..."
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3."
    exit 1
fi
echo "Python3 found: $(python3 --version)"

echo "Ensuring python3-venv is installed..."
sudo apt install -y python3-venv
if ! python3 -m venv --help &> /dev/null; then
    echo "Error: python3-venv is not available. Try running: sudo apt install python3-venv"
    exit 1
fi

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "Error: Could not create .venv. Please ensure python3-venv is installed and you have permission to write in this directory."
        echo "Try running: sudo apt install python3-venv"
        exit 1
    fi
    echo "Virtual environment .venv created."
    echo "Listing current directory contents for troubleshooting:"
    ls -l
    if [ ! -d ".venv" ]; then
        echo "Error: .venv directory was not created. Please check for errors above and ensure you have write permissions."
        exit 1
    fi
fi

echo "Activating virtual environment (.venv)..."
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
elif [ -f ".venv/Scripts/activate" ]; then
    # Fallback for environments que criam Scripts (ex: Windows WSL)
    source .venv/Scripts/activate
else
    echo "Error: Could not find the activate script in .venv/bin/activate or .venv/Scripts/activate."
    echo "The virtual environment may not have been created correctly or you are in the wrong directory."
    echo "Check if .venv exists and contains the 'activate' script."
    exit 1
fi

echo "Upgrading pip in venv (Ubuntu compatible)..."
python -m pip install --upgrade pip

echo "Installing dependencies: requests, pystray, Pillow (Ubuntu compatible)..."
python -m pip install requests pystray Pillow

echo "All dependencies installed in .venv!"
echo "To activate the environment manually: source .venv/bin/activate"
echo "-----------------------------------"
echo "Installation finished! To start QRZ Monitor, run: bash start-linux.sh"
echo "Ensuring pystray is installed..."
python -m pip install pystray
echo "pystray installation complete."
