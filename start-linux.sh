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
echo "Starting QRZ Monitor..."

if [ ! -d ".venv" ]; then
    echo "Virtual environment (.venv) not found!"
    echo "Run: bash install-linux.sh to install dependencies."
    exit 1
fi

echo "Choose mode to start QRZ Monitor:"
echo "1 - Auto-detect mode (tries GUI first, falls back to text)"
echo "2 - Force text mode only (recommended for servers/headless systems)"
echo "3 - Force text mode with safer startup (no GUI libraries)"
read -p "Enter 1, 2, or 3: " mode

if [ "$mode" = "1" ]; then
    echo "Starting QRZ Monitor in auto-detect mode..."
    .venv/bin/python3 qrz-monitor.py
elif [ "$mode" = "2" ]; then
    echo "Starting QRZ Monitor in text-only mode..."
    # Force text mode by setting environment variable
    QRZ_TEXT_MODE=1 .venv/bin/python3 qrz-monitor.py
elif [ "$mode" = "3" ]; then
    echo "Starting QRZ Monitor in safe text-only mode..."
    # Force text mode by unsetting DISPLAY
    unset DISPLAY
    QRZ_TEXT_MODE=1 .venv/bin/python3 qrz-monitor.py
else
    echo "Invalid option. Exiting."
    exit 1
fi