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
echo "=== QRZ Monitor Linux Installer ==="
echo "Updating package list..."
sudo apt update

echo "Installing Python3, pip, venv and tkinter..."
sudo apt install -y python3 python3-pip python3-venv python3-tk

echo "Creating local virtual environment (.venv)..."
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo "Error: Could not create .venv. Please ensure python3-venv is installed and you have permission to write in this directory."
    exit 1
fi

echo "Installing dependencies (requests, pystray, Pillow) in .venv..."
.venv/bin/pip3 install --upgrade pip
.venv/bin/pip3 install requests pystray Pillow

echo "-----------------------------------"
echo "Installation finished! To start QRZ Monitor, run: bash start-linux.sh"
