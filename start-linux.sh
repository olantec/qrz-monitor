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
echo "1 - Graphical interface (system tray, requires X11)"
echo "2 - Text mode (console only)"
read -p "Enter 1 or 2: " mode

if [ "$mode" = "1" ]; then
    echo "Starting QRZ Monitor in graphical mode..."
    .venv/bin/python3 qrz-monitor.py
elif [ "$mode" = "2" ]; then
    echo "Starting QRZ Monitor in text mode..."
    .venv/bin/python3 qrz-monitor-terminal.py
else
    echo "Invalid option. Exiting."
    exit 1
fi