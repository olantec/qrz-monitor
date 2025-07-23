#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRZ Monitor - Linux Safe Version
This version skips GUI completely on Linux and runs only in text mode
"""

import os
import sys

# Force text mode on Linux
if sys.platform.startswith('linux'):
    # Remove DISPLAY to force text mode
    if 'DISPLAY' in os.environ:
        del os.environ['DISPLAY']
    print("Linux detected - forcing text-only mode")

# Import the main module
from qrz_monitor import *

if __name__ == "__main__":
    # Force HAS_DISPLAY to False on Linux
    if sys.platform.startswith('linux'):
        global HAS_DISPLAY
        HAS_DISPLAY = False
        print("Running in Linux safe mode (text-only)")
    
    main()
