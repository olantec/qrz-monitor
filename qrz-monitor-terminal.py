# =====================
# Imports e variáveis globais
# =====================
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

CONFIG_FILE = 'config.ini'
QUEUE_FILE = 'pending_logs.pkl'
API_BASE_URL = "https://qrz.digital/api"
LOGIN_ENDPOINT = f"{API_BASE_URL}/auth/login"
ADDLOG_ENDPOINT = f"{API_BASE_URL}/logbook/adi"

config = configparser.ConfigParser()
auth_token = None
token_expiry = None
pending_logs = []
retry_thread = None
retry_running = False
udp_thread = None
running = False
sock = None

# =====================
# Funções utilitárias e de configuração
# =====================
def load_config():
    config.read(CONFIG_FILE)
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    defaults = {
        'Username': '',
        'Password': '',
        'UDPPort': '2333',
    }
    for key, default_value in defaults.items():
        if key not in config['DEFAULT']:
            config['DEFAULT'][key] = default_value
    if config['DEFAULT']['Username']:
        config['DEFAULT']['Username'] = config['DEFAULT']['Username'].upper()
    save_config()

def reload_config():
    global auth_token, token_expiry
    config.read(CONFIG_FILE)
    auth_token = None
    token_expiry = None
    print("🔄 Configuration reloaded from file")

def save_config():
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def encode_password(password):
    if not password:
        return ""
    try:
        password_bytes = password.encode('utf-8')
        encoded = base64.b64encode(password_bytes).decode('utf-8')
        return encoded
    except Exception as e:
        print(f"⚠️ Error encoding password: {e}")
        return password

def decode_password(encoded_password):
    if not encoded_password:
        return ""
    try:
        password_bytes = base64.b64decode(encoded_password)
        decoded = password_bytes.decode('utf-8')
        return decoded
    except Exception as e:
        print(f"⚠️ Password is not base64, using as plain text: {e}")
        return encoded_password

def get_password():
    encoded_password = config.get('DEFAULT', 'Password', fallback='')
    return decode_password(encoded_password)

def set_password(password):
    encoded_password = encode_password(password)
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    config['DEFAULT']['Password'] = encoded_password

def set_username(username):
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    config['DEFAULT']['Username'] = username.upper() if username else ''

def get_username():
    username = config.get('DEFAULT', 'Username', fallback='')
    return username.upper() if username else ''

# =====================
# Funções de autenticação e API
# =====================
def is_token_valid():
    global auth_token, token_expiry
    if not auth_token or not token_expiry:
        return False
    return datetime.now().timestamp() < token_expiry

def test_api_connectivity():
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return True
    except requests.exceptions.RequestException as e:
        return False

def authenticate():
    global auth_token, token_expiry
    username = get_username()
    password = get_password()
    if not username or not password:
        print("❌ Credentials not configured")
        return False
    if not test_api_connectivity():
        print("🌐 System offline - collection mode active (data will be sent when connected)")
        return False
    try:
        login_data = {"callsign": username, "password": password}
        response = requests.post(
            LOGIN_ENDPOINT,
            json=login_data,
            timeout=(5, 30),
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        )
        if response.status_code == 200:
            try:
                try:
                    result = response.json()
                    token_value = result.get('token') or result.get('access_token') or result.get('authToken')
                except json.JSONDecodeError:
                    token_value = response.text.strip()
                if token_value:
                    auth_token = token_value
                    token_expiry = datetime.now().timestamp() + 3600
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

# =====================
# Funções de fila de logs
# =====================
def load_pending_logs():
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
    try:
        with open(QUEUE_FILE, 'wb') as f:
            pickle.dump(pending_logs, f)
    except Exception as e:
        print(f"⚠️ Error saving logs queue: {e}")

def add_to_pending_queue(log_data):
    global pending_logs
    log_entry = {
        "data": log_data,
        "timestamp": datetime.now().isoformat(),
        "retry_count": 0,
        "next_retry": datetime.now().timestamp() + 10,
        "max_retries": 3
    }
    pending_logs.append(log_entry)
    save_pending_logs()

def clear_pending_queue():
    global pending_logs
    pending_logs = []
    save_pending_logs()

def process_pending_logs():
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
                delays = [10, 30, 60]
                delay = delays[min(log_entry["retry_count"] - 1, len(delays) - 1)]
                log_entry["next_retry"] = current_time + delay
                failed_logs.append(log_entry)
            else:
                log_entry["next_retry"] = 0
                log_entry["retry_count"] = 0
                failed_logs.append(log_entry)
    pending_logs = logs_to_keep + failed_logs
    save_pending_logs()

def process_startup_pending_logs():
    global pending_logs
    if not pending_logs:
        return
    current_time = datetime.now().timestamp()
    for log_entry in pending_logs:
        if log_entry["next_retry"] == 0:
            log_entry["next_retry"] = current_time + 5
    save_pending_logs()
    process_pending_logs()

# =====================
# Funções de UDP
# =====================
def udp_listener():
    global running, sock
    port = int(config.get('DEFAULT', 'UDPPort', fallback='2333'))
    host = '127.0.0.1'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.settimeout(1.0)
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
                        print(f"📡 Received from {addr}: {len(message)} bytes")
                        if message.strip().startswith('<?xml') or message.strip().startswith('<contactinfo'):
                            print(f"🔍 N1MM Logger XML detected")
                        # Sends processed message to server
                        send_log_with_retry(parsed_message)
            except UnicodeDecodeError:
                print(f"⚠️ Received non-UTF8 data from {addr}, ignoring...")
            
        except socket.timeout:
            continue # Returns to loop start to check 'running' flag
        except Exception as e:
            pass
    print("QRZ Monitor stopped.")
    if sock:
        sock.close()

def start_monitoring():
    global running, udp_thread
    if not running:
        load_pending_logs()
        auth_success = authenticate()
        if not auth_success:
            print("⚠️ Starting monitoring in offline mode - data will be collected and sent when possible")
        process_startup_pending_logs()
        start_retry_scheduler()
        running = True
        udp_thread = threading.Thread(target=udp_listener, daemon=True)
        udp_thread.start()
        if auth_success:
            print("QRZ Monitor started - waiting for JTDX/WSJT-X data...")
        else:
            print("QRZ Monitor started in offline mode - collecting data for later sending...")

def stop_monitoring():
    global running
    if running:
        running = False
        stop_retry_scheduler()
        if udp_thread:
            udp_thread.join(timeout=2)

def start_retry_scheduler():
    global retry_running, retry_thread
    if retry_running:
        return
    retry_running = True
    def retry_loop():
        config_check_counter = 0
        while retry_running:
            try:
                process_pending_logs()
                config_check_counter += 1
                if config_check_counter >= 3:
                    config_check_counter = 0
                    current_config = configparser.ConfigParser()
                    current_config.read(CONFIG_FILE)
                    current_username = current_config.get('DEFAULT', 'Username', fallback='').upper()
                    if current_username != get_username():
                        print("🔍 Configuration change detected - reloading...")
                        reload_config()
                time.sleep(10)
            except Exception as e:
                print(f"⚠️ Error in retry scheduler: {e}")
                time.sleep(30)
    retry_thread = threading.Thread(target=retry_loop, daemon=True)
    retry_thread.start()

def stop_retry_scheduler():
    global retry_running
    retry_running = False
    if retry_thread:
        retry_thread.join(timeout=2)

# =====================
# Funções de envio de log
# =====================
def send_to_qrz_server(log_data):
    global auth_token
    if not is_token_valid():
        print("Token expired, re-authenticating...")
        if not authenticate():
            print("❌ Could not authenticate - data will be stored for later sending")
            return False
    try:
        if not log_data:
            print("ℹ️ Message contains no valid log data")
            return False
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "text/plain",
            "Accept": "application/json"
        }
        print(f"Sending log: {log_data}")
        log_data = "<ORIGEM:11>QRZ-MONITOR " + str(log_data)
        response = requests.put(
            ADDLOG_ENDPOINT,
            data=log_data,
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

def send_log_with_retry(log_data):
    success = send_to_qrz_server(log_data)
    if success:
        print(f"✅ Log sent successfully!")
        return True
    else:
        print(f"⚠️ Send failed, adding to pending queue")
        add_to_pending_queue(log_data)
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
                # N1MM timestamp format: YYYY-MM-DD HH:MM:SS
                dt = datetime.strptime(timestamp.text, '%Y-%m-%d %H:%M:%S')
                qso_date = dt.strftime('%Y%m%d')
                time_on = dt.strftime('%H%M%S')
            except:
                pass
        
        # Converte frequência para MHz se necessário
        freq_mhz = ""
        if rxfreq is not None and rxfreq.text:
            try:
                freq_hz = float(rxfreq.text)
                freq_mhz = f"{freq_hz / 1000000:.6f}"
            except:
                pass
        
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
                'USB': 'SSB',
                'LSB': 'SSB',
                'CW': 'CW',
                'FM': 'FM',
                'AM': 'AM',
                'RTTY': 'RTTY',
                'PSK31': 'PSK31',
                'FT8': 'FT8',
                'FT4': 'FT4',
                'JT9': 'JT9',
                'JT65': 'JT65'
            }
            adif_mode = mode_mapping.get(mode.text.upper(), mode.text)
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

# =====================
# Funções auxiliares
# =====================
def check_credentials():
    """Checks if username and password are set. Prompts user if not configured."""
    username = get_username()
    password = get_password()
    if not username or not password:
        print("Username or password not set in config.ini.")
        # Prompt for callsign (always uppercase)
        while True:
            callsign = input("Enter your callsign (uppercase): ").strip().upper()
            if callsign:
                break
        set_username(callsign)
        # Prompt for password
        while True:
            pwd = input("Enter your password: ").strip()
            if pwd:
                break
        set_password(pwd)
        save_config()
        print("Credentials saved to config.ini.")

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
    print("\n".join(info_lines))

def on_quit():
    """Actions to be executed on exit."""
    stop_monitoring()
    print("Exiting QRZ Monitor...")
    sys.exit(0)

def main():
    load_config()
    check_credentials()
    load_pending_logs()
    if get_username():
        start_monitoring()
    
    # Show current status
    connection_status = "ONLINE (Authenticated)" if is_token_valid() else "CONNECTED (No auth)" if test_api_connectivity() else "OFFLINE"
    status_text = f"QRZ Monitor - {'RUNNING' if running else 'STOPPED'}\n{connection_status}"
    udp_port = config.get('DEFAULT', 'UDPPort', fallback='2333')
    status_text += f"\nUDP Port: {udp_port}"
    if pending_logs:
        status_text += f"\n{len(pending_logs)} pending logs"
    username = get_username()
    if username:
        status_text += f"\nUser: {username}"
    print(status_text)
    print("Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        on_quit()

if __name__ == "__main__":
    main()
