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
sudo apt install -y python3 python3-pip python3-venv

echo "Creating virtual environment (.venv)..."
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo "Error: Could not create .venv. Please ensure python3-venv is installed and you have permission to write in this directory."
    exit 1
fi

echo "Activating virtual environment (.venv)..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Error: Could not activate .venv. Please check Python and venv installation."
    exit 1
fi

echo "Upgrading pip in venv..."
.venv/bin/pip3 install --upgrade pip

echo "Installing dependencies: socket, threading, configparser, requests, json, time, pickle, os, base64, sys, datetime, pystray, Pillow, tkinter..."
.venv/bin/pip3 install requests pystray Pillow

echo "All dependencies installed in .venv!"
echo "To activate the environment manually: source .venv/bin/activate"
echo "-----------------------------------"
echo "Installation finished! To start QRZ Monitor, run: bash start-linux.sh"

echo "Imports required in your Python script:"
echo "import socket"
echo "import threading"
echo "import configparser"
echo "import requests"
echo "import json"
echo "import time"
echo "import pickle"
echo "import os"
echo "import base64"
echo "import sys"
echo "from datetime import datetime"
echo "from pystray import Icon, Menu, MenuItem"
echo "from PIL import Image, ImageDraw"
echo "import tkinter as tk"
