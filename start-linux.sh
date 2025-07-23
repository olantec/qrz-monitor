#!/bin/bash
# Starts QRZ Monitor on Linux
# Usage:
#   bash start-linux.sh
#
# This script will:
#   - Activate the Python virtual environment (.venv)
#   - Start QRZ Monitor

echo "=== QRZ Monitor Starter ==="
echo "This script will activate the Python virtual environment and start QRZ Monitor."
echo "If you see any errors about missing dependencies, run: bash install-linux.sh"
echo "-----------------------------------"

if [ -d ".venv" ]; then
    echo "Activating Python virtual environment (.venv)..."
    source .venv/bin/activate
else
    echo "Virtual environment (.venv) not found!"
    echo "Please run: bash install-linux.sh"
    exit 1
fi

echo "Starting QRZ Monitor..."
python3 qrz-monitor.py
