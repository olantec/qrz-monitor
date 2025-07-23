#!/bin/bash
# Installs QRZ Monitor dependencies for Linux (Debian, Ubuntu, Raspberry Pi)

echo "Updating package list..."
sudo apt update

echo "Installing Python3 and pip if needed..."
sudo apt install -y python3 python3-pip

# Check for externally-managed environment
python3 -m pip install --upgrade pip 2>&1 | grep 'externally-managed-environment' >/dev/null
if [ $? -eq 0 ]; then
    echo "Detected externally-managed Python environment. Using virtual environment (venv)."
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        echo "Virtual environment .venv created."
    fi
    source .venv/bin/activate
    echo "Upgrading pip in venv..."
    pip install --upgrade pip
    echo "Installing dependencies in venv..."
    pip install requests pystray Pillow
    echo "All dependencies installed in .venv!"
    echo "To activate the environment manually: source .venv/bin/activate"
else
    echo "Upgrading pip..."
    python3 -m pip install --upgrade pip
    echo "Installing dependencies globally..."
    python3 -m pip install requests pystray Pillow
    echo "All dependencies installed globally!"
fi
