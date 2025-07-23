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
echo "Checking for updates in the repository..."
GIT_OUTPUT=$(git pull)
if [[ "$GIT_OUTPUT" == *"Updating"* || "$GIT_OUTPUT" == *"changed"* || "$GIT_OUTPUT" == *"Fast-forward"* ]]; then
    echo "Repository updated. Please re-run this install script to ensure all changes are applied."
    exit 0
fi
echo "This script will install all dependencies for QRZ Monitor."
echo "If you see any errors, please check your internet connection and permissions."
echo "-----------------------------------"

echo "Updating package list..."
sudo apt update

echo "Installing Python3, pip and venv if needed..."
sudo apt install -y python3 python3-pip
echo "Checking Python3 installation..."
PYTHON_BIN=""
if command -v python3 &> /dev/null; then
    PYTHON_BIN="python3"
elif command -v python &> /dev/null; then
    PYTHON_BIN="python"
else
    echo "Error: Python is not installed or not found in PATH. Please install Python 3."
    exit 1
fi
echo "Python found: $PYTHON_BIN ($(which $PYTHON_BIN))"
$PYTHON_BIN --version

echo "Ensuring python3-venv is installed..."
sudo apt install -y python3-venv
if ! $PYTHON_BIN -m venv --help &> /dev/null; then
    echo "Error: venv module is not available for $PYTHON_BIN. Try running: sudo apt install python3-venv"
    exit 1
fi

if [ ! -d ".venv" ]; then
    $PYTHON_BIN -m venv .venv
    if [ $? -ne 0 ]; then
        echo "Warning: Could not create .venv with $PYTHON_BIN. Trying with python3..."
        python3 -m venv .venv
        if [ $? -ne 0 ]; then
            echo "Error: Could not create .venv with python3 either. Please ensure venv is available and you have permission to write in this directory."
            echo "Try running: sudo apt install python3-venv"
            exit 1
        fi
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

# Use PYTHON_BIN for all pip operations

echo "Upgrading pip in venv (Ubuntu compatible)..."
$PYTHON_BIN -m pip install --upgrade pip

echo "Installing dependencies: requests, pystray, Pillow (Ubuntu compatible)..."
$PYTHON_BIN -m pip install requests pystray Pillow

echo "All dependencies installed in .venv!"
echo "To activate the environment manually: source .venv/bin/activate"
echo "-----------------------------------"
echo "Installation finished! To start QRZ Monitor, run: bash start-linux.sh"
echo "Ensuring pystray is installed..."
$PYTHON_BIN -m pip install pystray

echo "pystray installation complete."
echo "Testing Python imports for dependencies..."
python <<EOF
try:
    import requests
    import pystray
    from PIL import Image
    print('All dependencies imported successfully!')
except ImportError as e:
    print(f'Import error: {e}')
    print('Some dependencies are missing or not installed correctly.')
EOF
