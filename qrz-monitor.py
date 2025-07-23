#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRZ Monitor - Ham Radio Log Monitor
Copyright (C) 2025 QRZ Digital
Licensed under MIT License

This is a legitimate ham radio logging application.
Purpose: Monitor UDP packets from logging software and sync with QRZ Digital.
"""

import socket
import threading
import configparser
import requests
import json
import time
import pickle
import os
import base64
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
import tkinter as tk


# --- Configuration ---
CONFIG_FILE = 'config.ini'
QUEUE_FILE = 'pending_logs.pkl'
config = configparser.ConfigParser()

# API Endpoints
API_BASE_URL = "https://qrz.digital/api"  # Fixed URL (removed "1")
LOGIN_ENDPOINT = f"{API_BASE_URL}/auth/login"
ADDLOG_ENDPOINT = f"{API_BASE_URL}/logbook/adi"  # Correct endpoint for logs

# Authentication token
auth_token = None
token_expiry = None

# Pending logs queue
pending_logs = []
retry_thread = None
retry_running = False

def load_config():
    """Loads configurations from config.ini file"""
    config.read(CONFIG_FILE)
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    
    # Ensures all necessary keys exist with default values
    defaults = {
        'Username': '',
        'Password': '',
        'UDPPort': '2333',
    }
    
    for key, default_value in defaults.items():
        if key not in config['DEFAULT']:
            config['DEFAULT'][key] = default_value
    
    # Converts username to uppercase if it exists
    if config['DEFAULT']['Username']:
        config['DEFAULT']['Username'] = config['DEFAULT']['Username'].upper()
    
    save_config()

def reload_config():
    """Reloads configurations from config.ini file"""
    global auth_token, token_expiry
    config.read(CONFIG_FILE)
    # Invalidates current token to force new authentication
    auth_token = None
    token_expiry = None
    print("🔄 Configuration reloaded from file")

def save_config():
    """Saves configurations to config.ini file"""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def encode_password(password):
    """Encodes password in base64"""
    if not password:
        return ""
    try:
        # Converts string to bytes and then to base64
        password_bytes = password.encode('utf-8')
        encoded = base64.b64encode(password_bytes).decode('utf-8')
        return encoded
    except Exception as e:
        print(f"⚠️ Error encoding password: {e}")
        return password  # Returns original in case of error

def decode_password(encoded_password):
    """Decodes password from base64"""
    if not encoded_password:
        return ""
    try:
        # Tries to decode as base64
        password_bytes = base64.b64decode(encoded_password)
        decoded = password_bytes.decode('utf-8')
        return decoded
    except Exception as e:
        # If it fails, assumes it's an unencoded password (backward compatibility)
        print(f"⚠️ Password is not base64, using as plain text: {e}")
        return encoded_password

def get_password():
    """Gets decoded password from configuration"""
    encoded_password = config.get('DEFAULT', 'Password', fallback='')
    return decode_password(encoded_password)

def set_password(password):
    """Sets encoded password in configuration"""
    encoded_password = encode_password(password)
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    config['DEFAULT']['Password'] = encoded_password

def set_username(username):
    """Sets username always in uppercase in configuration"""
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    config['DEFAULT']['Username'] = username.upper() if username else ''

def get_username():
    """Gets username always in uppercase from configuration"""
    username = config.get('DEFAULT', 'Username', fallback='')
    return username.upper() if username else ''

# --- Authentication and API ---
def test_api_connectivity():
    """Tests if the API is accessible"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return True
    except requests.exceptions.RequestException as e:
        return False

def authenticate():
    """Authenticates with QRZ Digital API and gets token"""
    global auth_token, token_expiry
    
    username = get_username()  # Uses function to ensure uppercase
    password = get_password()  # Uses function to decode password
    
    if not username or not password:
        print("❌ Credentials not configured")
        return False
    
    # First tests connectivity
    if not test_api_connectivity():
        print("🌐 System offline - collection mode active (data will be sent when connected)")
        return False
    
    try:
        login_data = {
            "callsign": username,
            "password": password
        }
        
        # More robust timeout settings
        response = requests.post(
            LOGIN_ENDPOINT, 
            json=login_data, 
            timeout=(5, 30),  # (connection timeout, read timeout)
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        )
        
        if response.status_code == 200:
            try:
                # First, tries to treat as JSON
                try:
                    result = response.json()
                    # Extracts token if it comes in JSON format
                    token_value = result.get('token') or result.get('access_token') or result.get('authToken')
                except json.JSONDecodeError:
                    # If not JSON, assumes it's a simple string (token)
                    token_value = response.text.strip()
                
                if token_value:
                    # Saves token and expiry in global variables
                    auth_token = token_value
                    token_expiry = datetime.now().timestamp() + 3600  # 1 hour
                    print(f"✓ Authenticated as {username} (token: {token_value[:10]}...)")
                    return True
                else:
                    print("✗ Empty or invalid token in response")
                    return False
                    
            except Exception as e:
                print(f"✗ Error processing authentication response: {e}")
                return False
        elif response.status_code == 401:
            print("🔐 Authentication error - check username and password in settings")
            return False
        elif response.status_code == 403:
            print("🚫 Access denied - check account permissions")
            return False
        else:
            print(f"❌ Authentication error: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print("⏱️ Authentication timeout - server may be slow")
        return False
    except requests.exceptions.ConnectionError:
        print("🌐 Connection error - system offline, collection mode active")
        return False
    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error in authentication - offline mode active")
        return False
    except Exception as e:
        print(f"❌ Unexpected error in authentication: {e}")
        return False

def is_token_valid():
    """Checks if token is still valid"""
    global auth_token, token_expiry
    if not auth_token or not token_expiry:
        return False
    return datetime.now().timestamp() < token_expiry

def send_to_qrz_server(message):
    """Sends data to QRZ Digital server"""
    global auth_token
    
    # Checks if token is valid, otherwise tries to authenticate
    if not is_token_valid():
        print("Token expired, re-authenticating...")
        if not authenticate():
            print("❌ Could not authenticate - data will be stored for later sending")
            return False
    
    try:
        # Parse UDP message (assuming WSJT-X/JTDX format)
        log_data = parse_udp_message(message)
        
        if not log_data:
            print("ℹ️ UDP message contains no valid log data")
            return False
        
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "text/plain",
            "Accept": "application/json"
        }
        
        print(f"Sending log: {log_data}")
        # Adds origin to the beginning of log_data
        log_data = "<ORIGEM:11>QRZ-MONITOR " + str(log_data)
        response = requests.put(
            ADDLOG_ENDPOINT,
            data=log_data,  # Uses 'data' for plain text
            headers=headers,
            timeout=(5, 30)
        )
        
        print(f"Log response status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f"✓ Log sent successfully!")
            return True
        else:
            print(f"❌ Error sending log: {response.status_code}")
            try:
                error_detail = response.json()
                print(f"Error details: {error_detail}")
            except:
                print(f"Error response: {response.text}")
            return False
            
    except requests.exceptions.Timeout as e:
        print(f"⏱️ Timeout sending log - data stored for retry")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"🌐 Connection error - system offline, data stored")
        return False
    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error - data stored for later sending")
        return False
    except Exception as e:
        print(f"❌ Unexpected error sending log: {e}")
        return False

def send_log_with_retry(message):
    """Sends log with retry system and persistence"""
    success = send_to_qrz_server(message)
    
    if success:
        print(f"✅ Log sent successfully!")
        return True
    else:
        # If it fails, adds to pending queue
        print(f"⚠️ Send failed, adding to pending queue")
        add_to_pending_queue(message)
        return False

def parse_udp_message(message):
    """Parse UDP message to extract log data."""
    try:
        if len(message.strip()) > 0:
            # Verifica se é XML (N1MM Logger Plus)
            if message.strip().startswith('<?xml') or message.strip().startswith('<contactinfo'):
                return parse_n1mm_xml(message)
            else:
                # Formato texto simples (WSJT-X/JTDX ou outros)
                return message
        else:
            return None
        
    except Exception as e:
        print(f"❌ Error parsing UDP message: {e}")
        return None

def parse_n1mm_xml(xml_data):
    """Parse N1MM Logger Plus XML format to ADIF format."""
    try:
        # Remove qualquer BOM ou caracteres especiais no início
        xml_data = xml_data.strip()
        if xml_data.startswith('\ufeff'):
            xml_data = xml_data[1:]
        
        # Parse do XML
        root = ET.fromstring(xml_data)
        
        # Extrai dados do XML
        call = root.find('call')
        mycall = root.find('mycall')
        band = root.find('band')
        mode = root.find('mode')
        timestamp = root.find('timestamp')
        rxfreq = root.find('rxfreq')
        txfreq = root.find('txfreq')
        snt = root.find('snt')
        rcv = root.find('rcv')
        gridsquare = root.find('gridsquare')
        name = root.find('name')
        qth = root.find('qth')
        comment = root.find('comment')
        
        # Converte timestamp do N1MM para formato ADIF
        qso_date = ""
        time_on = ""
        if timestamp is not None and timestamp.text:
            try:
                dt = datetime.strptime(timestamp.text, "%Y-%m-%d %H:%M:%S")
                qso_date = dt.strftime("%Y%m%d")
                time_on = dt.strftime("%H%M%S")
            except:
                # Fallback para timestamp atual
                now = datetime.now()
                qso_date = now.strftime("%Y%m%d")
                time_on = now.strftime("%H%M%S")
        
        # Converte frequência para MHz se necessário
        freq_mhz = ""
        if rxfreq is not None and rxfreq.text:
            try:
                freq_hz = int(rxfreq.text)
                freq_mhz = f"{freq_hz / 100000:.6f}"
            except:
                if band is not None and band.text:
                    # Converte banda para frequência aproximada
                    band_to_freq = {
                        "160": "1.8", "80": "3.5", "40": "7.0", "20": "14.0",
                        "17": "18.068", "15": "21.0", "12": "24.89", "10": "28.0",
                        "6": "50.0", "2": "144.0", "70": "432.0"
                    }
                    freq_mhz = band_to_freq.get(band.text, "14.0")
        
        # Monta string ADIF
        adif_fields = []
        
        if call is not None and call.text:
            adif_fields.append(f"<CALL:{len(call.text)}>{call.text}")
        
        if mycall is not None and mycall.text:
            adif_fields.append(f"<STATION_CALLSIGN:{len(mycall.text)}>{mycall.text}")
        
        if qso_date:
            adif_fields.append(f"<QSO_DATE:{len(qso_date)}>{qso_date}")
        
        if time_on:
            adif_fields.append(f"<TIME_ON:{len(time_on)}>{time_on}")
        
        if freq_mhz:
            adif_fields.append(f"<FREQ:{len(freq_mhz)}>{freq_mhz}")
        
        if band is not None and band.text:
            band_text = f"{band.text}M" if not band.text.endswith('M') else band.text
            adif_fields.append(f"<BAND:{len(band_text)}>{band_text}")
        
        if mode is not None and mode.text:
            # Converte modos N1MM para ADIF padrão
            mode_mapping = {
                "USB": "SSB", "LSB": "SSB", "CW": "CW",
                "RTTY": "RTTY", "PSK31": "PSK31", "PSK63": "PSK63",
                "JT65": "JT65", "JT9": "JT9", "FT8": "FT8", "FT4": "FT4"
            }
            adif_mode = mode_mapping.get(mode.text.upper(), mode.text.upper())
            adif_fields.append(f"<MODE:{len(adif_mode)}>{adif_mode}")
        
        if snt is not None and snt.text:
            adif_fields.append(f"<RST_SENT:{len(snt.text)}>{snt.text}")
        
        if rcv is not None and rcv.text:
            adif_fields.append(f"<RST_RCVD:{len(rcv.text)}>{rcv.text}")
        
        if gridsquare is not None and gridsquare.text:
            adif_fields.append(f"<GRIDSQUARE:{len(gridsquare.text)}>{gridsquare.text}")
        
        if name is not None and name.text:
            adif_fields.append(f"<NAME:{len(name.text)}>{name.text}")
        
        if qth is not None and qth.text:
            adif_fields.append(f"<QTH:{len(qth.text)}>{qth.text}")
        
        if comment is not None and comment.text:
            adif_fields.append(f"<COMMENT:{len(comment.text)}>{comment.text}")
        
        # Adiciona indicador de origem
        origem = "N1MM-LOGGER"
        adif_fields.append(f"<ORIGEM:{len(origem)}>{origem}")
        
        # Finaliza registro ADIF
        adif_record = " ".join(adif_fields) + " <EOR>"
        
        print(f"📡 N1MM XML converted to ADIF: {adif_record}")
        return adif_record
        
    except ET.ParseError as e:
        print(f"❌ XML Parse Error: {e}")
        return None
    except Exception as e:
        print(f"❌ Error parsing N1MM XML: {e}")
        return None


# --- Pending Logs Queue ---
def load_pending_logs():
    """Loads pending logs queue from file"""
    global pending_logs
    try:
        if os.path.exists(QUEUE_FILE):
            with open(QUEUE_FILE, 'rb') as f:
                pending_logs = pickle.load(f)
            print(f"📋 Loaded {len(pending_logs)} pending logs from queue")
        else:
            pending_logs = []
    except Exception as e:
        print(f"⚠️ Error loading logs queue: {e}")
        pending_logs = []

def save_pending_logs():
    """Saves pending logs queue to file"""
    try:
        with open(QUEUE_FILE, 'wb') as f:
            pickle.dump(pending_logs, f)
    except Exception as e:
        print(f"⚠️ Error saving logs queue: {e}")

def add_to_pending_queue(log_data):
    """Adds a log to pending sends queue"""
    global pending_logs
    
    log_entry = {
        "data": log_data,
        "timestamp": datetime.now().isoformat(),
        "retry_count": 0,
        "next_retry": datetime.now().timestamp() + 10,  # First attempt in 10s
        "max_retries": 3
    }
    
    pending_logs.append(log_entry)
    save_pending_logs()
    update_menu()  # Updates menu to show pending logs

def clear_pending_queue():
    """Clears pending logs queue"""
    global pending_logs
    pending_logs = []
    save_pending_logs()
    update_menu()

def process_pending_logs():
    """Processes pending logs queue with automatic retry"""
    global pending_logs
    
    if not pending_logs:
        return
    
    current_time = datetime.now().timestamp()
    logs_to_retry = []
    logs_to_keep = []
    
    for log_entry in pending_logs:
        if current_time >= log_entry["next_retry"]:
            logs_to_retry.append(log_entry)
        else:
            logs_to_keep.append(log_entry)
    
    if not logs_to_retry:
        return
    
    successful_logs = []
    failed_logs = []
    
    for log_entry in logs_to_retry:
        success = send_to_qrz_server(log_entry["data"])
        
        if success:
            successful_logs.append(log_entry)
        else:
            log_entry["retry_count"] += 1
            max_retries = log_entry.get("max_retries", 3)
            
            if log_entry["retry_count"] < max_retries:
                # Progressive backoff: 10s, 30s, 60s
                delays = [10, 30, 60]
                delay = delays[min(log_entry["retry_count"] - 1, len(delays) - 1)]
                log_entry["next_retry"] = current_time + delay
                failed_logs.append(log_entry)
            else:
                # After 3 attempts, marks for retry on next startup
                log_entry["next_retry"] = 0  # Will be tried on next startup
                log_entry["retry_count"] = 0  # Reset for next session
                failed_logs.append(log_entry)
    
    # Updates queue with logs that still need to be tried
    pending_logs = logs_to_keep + failed_logs
    save_pending_logs()
    
    if successful_logs:
        update_menu()  # Updates menu after successful sends

def start_retry_scheduler():
    """Starts thread that processes pending logs periodically"""
    global retry_running, retry_thread
    
    if retry_running:
        return
    
    retry_running = True
    
    def retry_loop():
        config_check_counter = 0
        while retry_running:
            try:
                process_pending_logs()
                # Updates tooltip every cycle
                update_menu()
                
                # Checks configuration changes every 30 seconds (3 cycles)
                config_check_counter += 1
                if config_check_counter >= 3:
                    config_check_counter = 0
                    # Checks if there were changes in configuration file
                    current_config = configparser.ConfigParser()
                    current_config.read(CONFIG_FILE)
                    current_username = current_config.get('DEFAULT', 'Username', fallback='').upper()
                    
                    if current_username != get_username():
                        print("🔍 Configuration change detected - reloading...")
                        reload_config()
                        update_menu()
                
                time.sleep(10)  # Checks every 10 seconds
            except Exception as e:
                print(f"⚠️ Error in retry scheduler: {e}")
                time.sleep(30)  # Waits longer in case of error
    
    retry_thread = threading.Thread(target=retry_loop, daemon=True)
    retry_thread.start()

def stop_retry_scheduler():
    """Stops retry scheduler thread"""
    global retry_running
    retry_running = False
    if retry_thread:
        retry_thread.join(timeout=2)

# --- UDP Monitoring ---
udp_thread = None
running = False
sock = None

def udp_listener():
    """Listens to UDP port and processes received data."""
    global running, sock
    port = int(config.get('DEFAULT', 'UDPPort', fallback='2333'))
    host = '127.0.0.1'
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.settimeout(1.0) # Timeout to allow thread stopping
    except OSError as e:
        print(f"❌ Network error: Could not listen on port {port}. Check if it's not in use. Error: {e}")
        stop_monitoring()
        return

    while running:
        try:
            data, addr = sock.recvfrom(65536)  # Buffer maior para XML do N1MM
            
            # Tries to decode as UTF-8 text
            try:
                message = data.decode('utf-8')
                if message.strip():
                    # Analisa e converte a mensagem
                    parsed_message = parse_udp_message(message)
                    if parsed_message:
                        print(f"� Received from {addr}: {len(message)} bytes")
                        if message.strip().startswith('<?xml') or message.strip().startswith('<contactinfo'):
                            print(f"🔍 N1MM Logger XML detected")
                        # Sends processed message to server
                        send_log_with_retry(parsed_message)
            except UnicodeDecodeError:
                print(f"⚠️ Received non-UTF8 data from {addr}, ignoring...")
            
        except socket.timeout:
            continue # Returns to loop start to check 'running' flag
        except Exception as e:
            print(f"⚠️ UDP listener error: {e}")
            time.sleep(1)  # Prevent rapid error loops
    
    print("QRZ Monitor stopped.")
    if sock:
        sock.close()

def process_startup_pending_logs():
    """Processes pending logs from previous startup"""
    global pending_logs
    
    if not pending_logs:
        return
    
    # Reschedules logs that were waiting for immediate attempt
    current_time = datetime.now().timestamp()
    for log_entry in pending_logs:
        if log_entry["next_retry"] == 0:  # Logs marked for next startup
            log_entry["next_retry"] = current_time + 5  # Tries in 5 seconds
    
    save_pending_logs()
    
    # Starts immediate processing
    process_pending_logs()

def start_monitoring():
    """Starts UDP monitoring thread."""
    global running, udp_thread
    if not running:
        # Loads pending logs first
        load_pending_logs()
        
        # Tries to authenticate, but continues even if it fails
        auth_success = authenticate()
        
        if not auth_success:
            print("⚠️ Starting monitoring in offline mode - data will be collected and sent when possible")
        
        # Processes pending logs from previous session
        process_startup_pending_logs()
        
        # Starts scheduler regardless of authentication
        start_retry_scheduler()
            
        running = True
        udp_thread = threading.Thread(target=udp_listener, daemon=True)
        udp_thread.start()
        update_menu()
        
        if auth_success:
            print("QRZ Monitor started - waiting for JTDX/WSJT-X data...")
        else:
            print("QRZ Monitor started in offline mode - collecting data for later sending...")

def stop_monitoring():
    """Stops UDP monitoring thread."""
    global running
    if running:
        running = False
        stop_retry_scheduler()
        if udp_thread:
            udp_thread.join(timeout=2)
        update_menu()

# --- Graphical Interface (Configuration) ---

def show_settings_dialog():
    """Opens configuration window directly in the same process"""
    try:
        import tkinter as tk
        from tkinter import Label, Entry, Button
        
        # Loads current configuration
        current_config = configparser.ConfigParser()
        current_config.read(CONFIG_FILE)
        
        if 'DEFAULT' not in current_config:
            current_config['DEFAULT'] = {
                'Username': '',
                'Password': '',
                'UDPPort': '2333',
            }

        root = tk.Tk()
        root.title("Settings - QRZ Monitor")
        root.resizable(False, False)
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        
        # Sets window icon
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'favicon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except Exception:
            pass

        def save_and_close():
            username_input = user_entry.get().strip()
            current_config.set('DEFAULT', 'Username', username_input.upper())
            encoded_password = encode_password(pass_entry.get())
            current_config.set('DEFAULT', 'Password', encoded_password)
            current_config.set('DEFAULT', 'UDPPort', port_entry.get())
            
            with open(CONFIG_FILE, 'w') as configfile:
                current_config.write(configfile)
            
            print("⚙️ Settings saved!")
            root.destroy()
            
            # Reloads configuration in main program
            reload_config()
            update_menu()

        def on_enter_key(event):
            save_and_close()
        
        def on_username_change(event):
            current_pos = user_entry.index(tk.INSERT)
            current_text = user_entry.get().upper()
            user_entry.delete(0, tk.END)
            user_entry.insert(0, current_text)
            user_entry.icursor(current_pos)

        # Creates fields
        Label(root, text="User (Callsign):").grid(row=0, column=0, padx=10, pady=8, sticky='w')
        user_entry = Entry(root, width=20, font=('Arial', 9))
        user_entry.grid(row=0, column=1, padx=10, pady=8)
        user_entry.insert(0, current_config.get('DEFAULT', 'Username', fallback='').upper())
        user_entry.bind('<Return>', on_enter_key)
        user_entry.bind('<KeyRelease>', on_username_change)

        Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=8, sticky='w')
        pass_entry = Entry(root, show="*", width=20, font=('Arial', 9))
        pass_entry.grid(row=1, column=1, padx=10, pady=8)
        pass_entry.insert(0, decode_password(current_config.get('DEFAULT', 'Password', fallback='')))
        pass_entry.bind('<Return>', on_enter_key)

        Label(root, text="UDP Port:").grid(row=2, column=0, padx=10, pady=8, sticky='w')
        port_entry = Entry(root, width=20, font=('Arial', 9))
        port_entry.grid(row=2, column=1, padx=10, pady=8)
        port_entry.insert(0, current_config.get('DEFAULT', 'UDPPort', fallback='2333'))
        port_entry.bind('<Return>', on_enter_key)

        # Frame for buttons
        button_frame = tk.Frame(root)
        button_frame.grid(row=3, columnspan=2, pady=15)
        
        save_button = Button(button_frame, text="Save", command=save_and_close, width=12, font=('Arial', 9))
        save_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = Button(button_frame, text="Cancel", command=root.destroy, width=12, font=('Arial', 9))
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Centers window on screen
        root.update_idletasks()
        width = root.winfo_reqwidth()
        height = root.winfo_reqheight()
        
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Focus on first field
        user_entry.focus_set()
        user_entry.selection_range(0, tk.END)
        
        # Removes topmost after some time
        root.after(1000, lambda: root.attributes('-topmost', False))
        
        print("⚙️ Settings window opened...")
        root.mainloop()
        print("⚙️ Settings window closed")
        
    except Exception as e:
        print(f"❌ Error opening settings: {e}")
        # Fallback: shows instructions
        print("💡 To configure manually:")
        print(f"   1. Edit config.ini file")
        print(f"   2. Section [DEFAULT]:")
        print(f"   3. Username = YOUR_CALLSIGN")
        print(f"   4. Password = YOUR_PASSWORD")
        print(f"   5. UDPPort = 2333")


# --- System Tray Icon and Menu ---
icon = None

def load_icon():
    """Loads application icon from favicon.ico file"""
    return get_status_icon()

def create_simple_icon(width, height, status_color='blue'):
    """Creates a simple image for icon as fallback."""
    image = Image.new('RGB', (width, height), 'black')
    dc = ImageDraw.Draw(image)
    
    # Defines color based on status
    if status_color == 'green':
        fill_color = '#00AA00'  # Darker green for online
        border_color = '#00FF00'  # Light green for border
    elif status_color == 'yellow':
        fill_color = '#AA8800'  # Darker yellow for connected
        border_color = '#FFFF00'  # Light yellow for border
    elif status_color == 'red':
        fill_color = '#AA0000'   # Darker red for offline
        border_color = '#FF0000'  # Light red for border
    else:
        fill_color = '#000088'      # Dark blue default
        border_color = '#0000FF'    # Light blue for border
    
    # Draws a colored circle
    margin = 8
    dc.ellipse([margin, margin, width-margin, height-margin], fill=fill_color, outline=border_color, width=3)
    
    # Adds status indicator in center
    center_x, center_y = width // 2, height // 2
    if status_color == 'green':
        # Draws a check (✓) for online
        dc.line([center_x-8, center_y, center_x-3, center_y+5], fill='white', width=3)
        dc.line([center_x-3, center_y+5, center_x+8, center_y-5], fill='white', width=3)
    elif status_color == 'yellow':
        # Draws an exclamation point (!) for connected
        dc.rectangle([center_x-2, center_y-8, center_x+2, center_y+2], fill='white')
        dc.rectangle([center_x-2, center_y+5, center_x+2, center_y+8], fill='white')
    elif status_color == 'red':
        # Draws an X for offline
        dc.line([center_x-6, center_y-6, center_x+6, center_y+6], fill='white', width=3)
        dc.line([center_x-6, center_y+6, center_x+6, center_y-6], fill='white', width=3)
    else:
        # Draws a dot for default
        dc.ellipse([center_x-4, center_y-4, center_x+4, center_y+4], fill='white')
    
    return image

def get_status_icon():
    """Returns a colored icon based on connection status"""
    try:
        # Tries to load favicon.ico first
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'favicon.ico')
        if os.path.exists(icon_path):
            return Image.open(icon_path)
    except Exception as e:
        pass
    
    # If can't load favicon, creates colored icon based on status
    if is_token_valid():
        return create_simple_icon(64, 64, 'green')
    elif test_api_connectivity():
        return create_simple_icon(64, 64, 'yellow')
    else:
        return create_simple_icon(64, 64, 'red')

def show_pending_logs_info():
    """Shows detailed information of pending logs"""
    if not pending_logs:
        print("📋 Pending Logs: No pending logs in queue.")
        return
    
    info_lines = [f"📋 Total pending logs: {len(pending_logs)}"]
    
    for i, log_entry in enumerate(pending_logs, 1):
        timestamp = log_entry.get('timestamp', 'N/A')
        retry_count = log_entry.get('retry_count', 0)
        max_retries = log_entry.get('max_retries', 3)
        
        if log_entry.get('next_retry', 0) == 0:
            status = "Waiting for next session"
        else:
            next_retry_time = datetime.fromtimestamp(log_entry.get('next_retry', 0))
            status = f"Next attempt: {next_retry_time.strftime('%H:%M:%S')}"
        
        info_lines.append(f"Log {i}:")
        info_lines.append(f"  📅 Created: {timestamp}")
        info_lines.append(f"  🔄 Attempts: {retry_count}/{max_retries}")
        info_lines.append(f"  ⏰ Status: {status}")
        info_lines.append("")
    
    # Displays in console instead of messagebox
    print("\n".join(info_lines))

def get_connection_status():
    """Returns connection and authentication status"""
    if is_token_valid():
        return "● ONLINE (Authenticated)"
    elif test_api_connectivity():
        return "◐ CONNECTED (No auth)"
    else:
        return "○ OFFLINE"

def get_connection_status_with_color():
    """Returns connection status with alternative colored indicators"""
    if is_token_valid():
        return "● Online (Authenticated)"  # Filled circle
    elif test_api_connectivity():
        return "◐ Connected (No auth)"  # Half circle
    else:
        return "○ Offline"  # Empty circle

def get_tooltip_text():
    """Generates tooltip text with dynamic information"""
    connection_status = get_connection_status()
    
    # Basic status with more visible symbols
    if running:
        status_text = f"▶ QRZ Monitor - RUNNING\n{connection_status}"
    else:
        status_text = f"⏸ QRZ Monitor - STOPPED\n{connection_status}"
    
    # Current UDP port with safe default value
    udp_port = config.get('DEFAULT', 'UDPPort', fallback='2333')
    status_text += f"\n⚡ UDP Port: {udp_port}"
    
    # Pending logs information
    if pending_logs:
        pending_count = len(pending_logs)
        status_text += f"\n� {pending_count} pending log{'s' if pending_count != 1 else ''}"
        
        # Shows next retry if available
        current_time = datetime.now().timestamp()
        next_retry_logs = [log for log in pending_logs if log.get('next_retry', 0) > current_time]
        
        if next_retry_logs:
            next_retry_time = min(log.get('next_retry', 0) for log in next_retry_logs)
            time_diff = int(next_retry_time - current_time)
            
            if time_diff > 60:
                time_str = f"{time_diff // 60}min {time_diff % 60}s"
            else:
                time_str = f"{time_diff}s"
            
            status_text += f"\n⏱ Next send in {time_str}"
    else:
        status_text += f"\n✓ No pending logs"
    
    # Configured user with safe default value
    username = get_username()  # Uses function to ensure uppercase
    if username:
        status_text += f"\n👤 User: {username}"
    else:
        status_text += f"\n⚠ User not configured"
    
    return status_text

def get_menu():
    """Creates menu dynamically based on 'running' state."""
    connection_status = get_connection_status()
    
    if running:
        yield MenuItem(f'Status: ▶️ Running ({connection_status})', None, enabled=False)
        if pending_logs:
            yield MenuItem(f'� Pending logs: {len(pending_logs)}', show_pending_logs_info)
        yield MenuItem('⏸️ Stop Monitoring', stop_monitoring)
    else:
        yield MenuItem(f'Status: ⏸️ Stopped ({connection_status})', None, enabled=False)
        if pending_logs:
            yield MenuItem(f'� Pending logs: {len(pending_logs)}', show_pending_logs_info)
        yield MenuItem('▶️ Start Monitoring', start_monitoring)
    
    yield Menu.SEPARATOR
    yield MenuItem('⚙️ Settings', show_settings_dialog)
    if pending_logs:
        yield MenuItem('🔄 Process Queue Now', lambda: process_pending_logs())
        yield MenuItem('🗑 Clear Queue', clear_pending_queue)
    yield MenuItem('🔌 Try Reconnect', lambda: authenticate())
    yield MenuItem('❌ Exit', on_quit)

def get_dynamic_app_name():
    """Generates dynamic application name with status"""
    base_name = "QRZ Monitor"
    
    if running:
        if is_token_valid():
            return f"{base_name} [ONLINE]"
        elif test_api_connectivity():
            return f"{base_name} [CONNECTED]"
        else:
            return f"{base_name} [OFFLINE]"
    else:
        return f"{base_name} [STOPPED]"

def update_menu():
    """Updates tray menu, tooltip and icon."""
    if icon:
        icon.menu = Menu(get_menu)
        # Updates tooltip with dynamic information
        icon.title = get_tooltip_text()
        # Updates icon based on status
        try:
            icon.icon = get_status_icon()
            # Tries to update application name (not all systems support this)
            icon.name = get_dynamic_app_name()
        except Exception as e:
            pass  # Ignores error if can't update icon

def on_quit():
    """Actions to be executed on exit."""
    stop_monitoring()
    if icon:
        icon.stop()

def main():
    global icon
    
    load_config()
    load_pending_logs()  # Loads pending logs on startup
    
    # Creates tray icon using favicon.ico
    icon_image = load_icon()
    initial_tooltip = get_tooltip_text()
    dynamic_name = get_dynamic_app_name()
    icon = Icon(dynamic_name, icon_image, initial_tooltip, menu=Menu(get_menu))
    
    # Starts monitoring if there's a configured user
    if get_username():  # Uses function to ensure uppercase
        start_monitoring()

    icon.run()

if __name__ == "__main__":
    main()
