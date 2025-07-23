#!/bin/bash
# Starts QRZ Monitor on Linux

# Function to check dependencies
check_deps() {
    python3 --version >/dev/null 2>&1 || return 1
    python3 -m pip --version >/dev/null 2>&1 || return 1
    python3 -c "import requests, pystray, PIL" >/dev/null 2>&1 || return 1
    return 0
}

echo "Checking dependencies..."
if check_deps; then
    echo "All dependencies are already installed."
else
    echo "Missing dependencies. Installing..."
    ./install-linux.sh
fi

# Start the monitor
python3 qrz-monitor.py
