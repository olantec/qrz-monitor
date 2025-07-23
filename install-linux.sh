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
sudo apt install -y python3 python3-pip python3-venv

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "Virtual environment .venv created."
fi

echo "Activating virtual environment (.venv)..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Error: Could not activate .venv. Please check Python and venv installation."
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
