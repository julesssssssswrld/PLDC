"""
PLDT WiFi Manager - Backend Server
Pure HTTP requests to router, no browser automation.
"""

import os
import json
import time
import binascii
import threading
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# Configuration
# ============================================================

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Server configuration
SERVER_PORT = 80                 # Use port 80 for web access

# File paths
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')

# Router configuration
ROUTER_BASE_URL = "https://192.168.1.1"
AES_KEY = "opqrstuvwxyz{|}~".encode('utf-8')
AES_IV = "opqrstuvwxyz{|}~".encode('utf-8')


# ============================================================
# Helper Functions
# ============================================================

config_lock = threading.Lock()

def load_config():
    """Load configuration from JSON file"""
    with config_lock:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {
            "router_url": ROUTER_BASE_URL,
            "username": "",
            "password": "",
            "is_authenticated": False
        }


def save_config(config):
    """Save configuration to JSON file"""
    with config_lock:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)


def format_time_remaining(expire_timestamp):
    """Format remaining time as HH:MM:SS, or return None if expired"""
    now = int(time.time())
    remaining = expire_timestamp - now
    if remaining <= 0:
        return None
    hours = remaining // 3600
    minutes = (remaining % 3600) // 60
    seconds = remaining % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def process_expired_devices(router_instance):
    """Remove expired public SSID devices from whitelist and config using the given router instance.

    Uses atomic read-modify-write pattern to prevent race conditions.
    Only called from the background cleanup thread.
    """
    # Hold the config lock for the entire read-modify-write cycle
    with config_lock:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            config = {
                "router_url": ROUTER_BASE_URL,
                "username": "",
                "password": "",
                "is_authenticated": False
            }

        public_ssid_allowed = config.get("public_ssid_allowed", {})
        current_time = int(time.time())
        expired_macs = []

        for mac, data in list(public_ssid_allowed.items()):
            expire_time = data.get("expires", 0) if isinstance(data, dict) else 0
            if current_time >= expire_time:
                # Mark as expired - we'll clean up config regardless of router removal result
                expired_macs.append(mac)
                # Attempt to remove from router whitelist (best effort)
                # This may fail if device already left or was manually removed, which is fine
                router_instance.remove_mac_from_whitelist(mac)

        # Always clean up expired entries from config, regardless of router removal result
        if expired_macs:
            for mac in expired_macs:
                if mac in public_ssid_allowed:
                    del public_ssid_allowed[mac]
            config["public_ssid_allowed"] = public_ssid_allowed
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)

        return expired_macs


# ============================================================
# Router API Class
# ============================================================

class PLDTRouter:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session_id = None
        self.is_connected = False
        self.last_error = None
        self._lock = threading.RLock()  # Reentrant lock for thread safety

    def ensure_connected(self):
        """Ensure router is connected, attempt login if not. Returns True if connected."""
        with self._lock:
            if self.is_connected:
                return True
            config = load_config()
            if config.get("username") and config.get("password"):
                return self.login(config["username"], config["password"])
            return False

    def fhencrypt(self, password):
        """Encrypt password using AES-128-CBC"""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_data = pad(password.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return binascii.hexlify(encrypted).decode('utf-8').upper()
    
    def parse_response(self, text):
        """Parse router response (strips headers if present)"""
        json_start = text.find('{')
        if json_start == -1:
            return None
        try:
            return json.loads(text[json_start:])
        except json.JSONDecodeError:
            return None
    
    def login(self, username, password):
        """Login to router with encrypted password"""
        with self._lock:
            try:
                config = load_config()
                router_url = config.get('router_url', ROUTER_BASE_URL)

                # Step 1: Access login page to init session
                self.session.get(f"{router_url}/fh", verify=False, timeout=10)

                # Step 2: Get session ID (like XHR.post does via get_refresh_sessionid)
                session_resp = self.session.get(
                    f"{router_url}/cgi-bin/ajax",
                    params={
                        "ajaxmethod": "get_refresh_sessionid",
                        "_": str(int(time.time() * 1000))
                    },
                    verify=False,
                    timeout=10
                )
                session_data = self.parse_response(session_resp.text)
                if session_data and "sessionid" in session_data:
                    self.session_id = session_data["sessionid"]
                else:
                    # Fallback: try direct text
                    self.session_id = session_resp.text.strip()

                # Step 3: Encrypt password and build login data
                encrypted_password = self.fhencrypt(password)

                # Build form data like XHR._encode_new does:
                login_data = {
                    "username": username,
                    "loginpd": encrypted_password,
                    "port": "0",
                    "sessionid": self.session_id,
                    "ajaxmethod": "do_login",
                    "fhAccess": "1",
                    "_": str(int(time.time() * 1000))
                }

                # Step 4: POST to /cgi-bin/ajax
                login_resp = self.session.post(
                    f"{router_url}/cgi-bin/ajax",
                    data=login_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    verify=False,
                    timeout=10
                )

                # Parse login response
                login_result = self.parse_response(login_resp.text)

                # Step 5: Verify login - check login_result
                if login_result and login_result.get("login_result") == 0:
                    self.is_connected = True
                    # Refresh session ID after successful login
                    session_resp = self.session.get(
                        f"{router_url}/cgi-bin/ajax",
                        params={
                            "ajaxmethod": "get_refresh_sessionid",
                            "_": str(int(time.time() * 1000))
                        },
                        verify=False,
                        timeout=10
                    )
                    session_data = self.parse_response(session_resp.text)
                    if session_data and "sessionid" in session_data:
                        self.session_id = session_data["sessionid"]
                    return True
                else:
                    self.last_error = f"Login failed: result={login_result}"
                    self.is_connected = False
                    print(f"Login failed for user: {username}. Result: {login_result}")
                    return False

            except Exception as e:
                self.last_error = str(e)
                self.is_connected = False
                print(f"Login encountered an exception: {e}")
                return False

    def api_call(self, method, extra_params=None):
        """Make API call to router"""
        with self._lock:
            try:
                config = load_config()
                router_url = config.get('router_url', ROUTER_BASE_URL)

                params = {
                    "ajaxmethod": method,
                    "sessionid": self.session_id,
                    "_": str(int(time.time() * 1000))
                }
                if extra_params:
                    params.update(extra_params)

                response = self.session.get(
                    f"{router_url}/cgi-bin/ajax",
                    params=params,
                    verify=False,
                    timeout=10
                )
                return self.parse_response(response.text)
            except Exception as e:
                self.last_error = str(e)
                return None

    def refresh_session_id(self):
        """Refresh session ID before POST requests (required by router)"""
        # Note: Called within _lock context from api_post, uses RLock so safe to call
        try:
            config = load_config()
            router_url = config.get('router_url', ROUTER_BASE_URL)

            resp = self.session.get(
                f"{router_url}/cgi-bin/ajax",
                params={
                    "ajaxmethod": "get_refresh_sessionid",
                    "_": str(int(time.time() * 1000))
                },
                verify=False,
                timeout=10
            )
            result = self.parse_response(resp.text)
            if result and 'sessionid' in result:
                self.session_id = result['sessionid']
                return True
        except Exception as e:
            print(f"Error refreshing session: {e}")
        return False

    def api_post(self, method, data):
        """Make POST API call to router"""
        with self._lock:
            try:
                config = load_config()
                router_url = config.get('router_url', ROUTER_BASE_URL)

                # Refresh session ID before POST
                self.refresh_session_id()

                # All parameters go in POST body
                import random
                post_data = {
                    "ajaxmethod": method,
                    "sessionid": self.session_id,
                    "_": str(random.random()),
                }
                # Merge with action-specific data
                post_data.update(data)

                response = self.session.post(
                    f"{router_url}/cgi-bin/ajax",
                    data=post_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    verify=False,
                    timeout=10
                )

                print(f"DEBUG api_post {method} status={response.status_code}")

                # Check if response indicates session invalid
                result = self.parse_response(response.text)
                if result and result.get("session_valid") == 0:
                    # Session expired, try to re-login and retry
                    config = load_config()
                    if config.get("username") and config.get("password"):
                        if self.login(config["username"], config["password"]):
                            # Refresh session and retry
                            self.refresh_session_id()
                            post_data["sessionid"] = self.session_id
                            post_data["_"] = str(random.random())
                            response = self.session.post(
                                f"{router_url}/cgi-bin/ajax",
                                data=post_data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                                verify=False,
                                timeout=10
                            )
                            print(f"DEBUG api_post RETRY {method} status={response.status_code}")

                # Check for success
                if response.status_code == 200:
                    result = self.parse_response(response.text)
                    if result and result.get("error"):
                        self.last_error = result.get("error")
                        return False
                    return True
                else:
                    self.last_error = f"HTTP {response.status_code}"
                    return False
            except Exception as e:
                self.last_error = str(e)
                return False

    def get_ssid_mappings(self):
        """Get SSID name mappings from vlanbind API"""
        with self._lock:
            try:
                config = load_config()
                router_url = config.get('router_url', ROUTER_BASE_URL)

                params = {
                    "ajaxmethod": "vlanbind",
                    "sessionid": self.session_id,
                    "_": str(int(time.time() * 1000))
                }

                resp = self.session.get(
                    f"{router_url}/cgi-bin/ajax",
                    params=params,
                    verify=False,
                    timeout=10
                )

                data = self.parse_response(resp.text)

                ssid_map = {}
                if data and "wifi_obj_enable" in data:
                    wifi_obj = data["wifi_obj_enable"]
                    for key, value in wifi_obj.items():
                        if key.startswith("ssid") and value:
                            ssid_map[key] = value

                return ssid_map

            except Exception as e:
                print(f"Error getting SSID mappings: {e}")
                return {}

    def parse_layer2_interface(self, layer2_interface, interface_type, ssid_map):
        """Parse Layer2Interface to get human-readable connection info."""
        if not layer2_interface:
            return interface_type or "Connected"
        
        # Handle Ethernet connections
        if "LANEthernetInterfaceConfig" in layer2_interface:
            import re
            match = re.search(r'LANEthernetInterfaceConfig\.(\d+)', layer2_interface)
            if match:
                port_num = int(match.group(1))
                return f"LAN Port {port_num}"
            return "Ethernet"
        
        # Handle WiFi connections
        if "WLANConfiguration" in layer2_interface:
            import re
            match = re.search(r'WLANConfiguration\.(\d+)', layer2_interface)
            if match:
                wlan_index = match.group(1)
                ssid_key = f"ssid{wlan_index}"
                
                if ssid_key in ssid_map:
                    ssid_name = ssid_map[ssid_key]
                    if int(wlan_index) >= 5:
                        return f"{ssid_name} (5G)"
                    else:
                        return f"{ssid_name} (2.4G)"
                else:
                    if interface_type == "5G" or int(wlan_index) >= 5:
                        return "5G"
                    else:
                        return "2.4G"
        
        # Fallback
        return interface_type or "Connected"
    
    def get_connected_devices(self):
        """Get all connected devices from router"""
        with self._lock:
            if not self.is_connected:
                return []

            try:
                config = load_config()
                router_url = config.get('router_url', ROUTER_BASE_URL)

                # Get SSID mappings first
                ssid_map = self.get_ssid_mappings()

                params = {
                    "ajaxmethod": "get_lan_status",
                    "sessionid": self.session_id,
                    "fhAccess": "1",
                    "_": str(int(time.time() * 1000))
                }

                resp = self.session.get(
                    f"{router_url}/cgi-bin/ajax",
                    params=params,
                    verify=False,
                    timeout=10
                )

                data = self.parse_response(resp.text)

                # Check for session invalidation
                if data and data.get("session_valid") == 0:
                    print("Session invalid detected in response. Re-logging in...")
                    config = load_config()
                    if config.get("username") and config.get("password"):
                        if self.login(config["username"], config["password"]):
                            # Update session_id in params
                            params["sessionid"] = self.session_id
                            # Retry request
                            resp = self.session.get(
                                f"{router_url}/cgi-bin/ajax",
                                params=params,
                                verify=False,
                                timeout=10
                            )
                            data = self.parse_response(resp.text)

                devices = []

                def convert_ip(ip_str):
                    if ip_str and "_point_" in ip_str:
                        return ip_str.replace("_point_", ".")
                    return ip_str

                # Parse get_lan_status structure
                if data and "get_lan_status" in data:
                    lan_status = data["get_lan_status"]
                    items = lan_status.get("dhcp_user_list", [])

                    if isinstance(items, list) and len(items) > 0:
                        for item in items:
                            mac = item.get("MACAddress", "")
                            if not mac:
                                continue

                            ip = convert_ip(item.get("IPAddress", "") or "")
                            hostname = item.get("HostName", "") or "Unknown"

                            layer2_interface = item.get("Layer2Interface", "")
                            interface_type = item.get("InterfaceType", "") or item.get("AccessType", "")
                            connection = self.parse_layer2_interface(layer2_interface, interface_type, ssid_map)

                            devices.append({
                                "id": mac.upper(),
                                "mac": mac.upper(),
                                "ip": ip,
                                "name": hostname,
                                "active": item.get("Active", "1") == "1",
                                "status": "active" if item.get("Active", "1") == "1" else "inactive",
                                "connection": connection
                            })

                # Also check legacy format
                if not devices and data and "lan_status" in data and "data" in data.get("lan_status", {}):
                    items = data["lan_status"]["data"]
                    if isinstance(items, list):
                        for item in items:
                            mac = item.get("MACAddress", "")
                            if not mac:
                                continue

                            ip = convert_ip(item.get("IPAddress", "") or "")
                            hostname = item.get("HostName", "") or "Unknown"

                            layer2_interface = item.get("Layer2Interface", "")
                            interface_type = item.get("InterfaceType", "") or item.get("AccessType", "")
                            connection = self.parse_layer2_interface(layer2_interface, interface_type, ssid_map)

                            devices.append({
                                "id": mac.upper(),
                                "mac": mac.upper(),
                                "ip": ip,
                                "name": hostname,
                                "active": item.get("Active", "1") == "1",
                                "status": "active" if item.get("Active", "1") == "1" else "inactive",
                                "connection": connection
                            })

                print(f"DEBUG DEVICES FOUND: {len(devices)}")
                return devices

            except Exception as e:
                print(f"Error getting devices: {e}")
                import traceback
                traceback.print_exc()
                return []

    def get_mac_whitelist(self):
        """Get current MAC whitelist"""
        data = self.api_call("get_ipv4_mac_filter_info")
        if data:
            return data
        return {"MACFEnable": "0", "MACFMode": "1", "mac_filter_info": []}
    
    def add_mac_to_whitelist(self, mac_address):
        """Add MAC address to whitelist"""
        data = {
            "action": "add",
            "MAC": mac_address.upper(),
            "TimeStart": "00:00",
            "TimeStop": "23:59",
            "Enable": "1"
        }
        return self.api_post("set_ipv4_mac_filter_info", data)
    
    def remove_mac_from_whitelist(self, mac_address):
        """Remove MAC address from whitelist by finding its index"""
        whitelist = self.get_mac_whitelist()
        mac_filter_info = whitelist.get("ipv4_mac_filter_info", {})
        if isinstance(mac_filter_info, dict):
            mac_list = mac_filter_info.get("mac_filter_data", [])
            if isinstance(mac_list, list):
                for entry in mac_list:
                    if entry.get("MAC", "").upper() == mac_address.upper():
                        index = entry.get("ipv4_mac_filter_index", None)
                        if index is not None:
                            data = {
                                "action": "delete",
                                "ipv4_mac_filter_index": str(index)
                            }
                            return self.api_post("set_ipv4_mac_filter_info", data)
        return False

    def is_private_connection(self, connection_string):
        """Check if a connection is from a private/trusted source (LAN or private SSID)"""
        if not connection_string:
            return False

        # LAN ports are always considered private
        if connection_string.startswith("LAN Port"):
            return True

        # Check against private SSIDs from config
        config = load_config()
        private_ssids = config.get("private_ssids", [])

        for ssid in private_ssids:
            if ssid in connection_string:
                return True

        return False


# Global router instance
router = PLDTRouter()

# Background cleanup thread control
cleanup_thread = None
cleanup_stop_event = threading.Event()


def cleanup_expired_devices():
    """Background thread that periodically checks for and removes expired public SSID devices."""
    print("Background cleanup thread started.")

    while not cleanup_stop_event.is_set():
        try:
            config = load_config()
            if config.get("public_ssid_allowed", {}):
                # Try to connect to router for whitelist removal (best effort)
                router_connected = router.ensure_connected()
                if not router_connected:
                    print("Background cleanup: Router not connected, will still clean up config.")

                # Always attempt cleanup - router removal is best effort
                expired_macs = process_expired_devices(router)
                if expired_macs:
                    print(f"Background cleanup: Removed {len(expired_macs)} expired device(s).")
        except Exception as e:
            print(f"Background cleanup error: {e}")

        # Wait for 15 seconds before next check, but check stop event every second
        # Reduced from 60s to 15s for faster expired device removal
        for _ in range(15):
            if cleanup_stop_event.is_set():
                break
            time.sleep(1)

    print("Background cleanup thread stopped.")


def start_cleanup_thread():
    """Start the background cleanup thread."""
    global cleanup_thread
    if cleanup_thread is None or not cleanup_thread.is_alive():
        cleanup_stop_event.clear()
        cleanup_thread = threading.Thread(target=cleanup_expired_devices, daemon=True)
        cleanup_thread.start()


def stop_cleanup_thread():
    """Stop the background cleanup thread."""
    cleanup_stop_event.set()
    global cleanup_thread
    if cleanup_thread is not None and hasattr(cleanup_thread, 'is_alive') and cleanup_thread.is_alive():
        cleanup_thread.join(timeout=5)


# ============================================================
# API Routes
# ============================================================

@app.route('/')
def serve_index():
    """Serve admin panel"""
    return send_from_directory('.', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('.', path)


# --- Status ---

@app.route('/api/status')
def get_status():
    """Get system status (for header indicator)"""
    config = load_config()
    
    if not config.get("username") or not config.get("password"):
        return jsonify({"status": "gray", "message": "No credentials saved"})
    
    if not router.is_connected:
        # Try to reconnect
        if router.login(config["username"], config["password"]):
            return jsonify({"status": "green", "message": "Connected"})
        return jsonify({"status": "red", "message": "Authentication failed"})
    
    return jsonify({"status": "green", "message": "Connected"})


# --- Authentication ---

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login with router credentials"""
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    
    if router.login(username, password):
        config = load_config()
        config["username"] = username
        config["password"] = password
        config["is_authenticated"] = True
        save_config(config)
        return jsonify({"success": True, "message": "Login successful"})
    
    return jsonify({"success": False, "message": router.last_error or "Authentication failed"})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout and clear credentials"""
    config = load_config()
    config["username"] = ""
    config["password"] = ""
    config["is_authenticated"] = False
    save_config(config)
    router.is_connected = False
    return jsonify({"success": True})


@app.route('/api/auth/status')
def auth_status():
    """Get authentication status"""
    config = load_config()
    return jsonify({
        "is_authenticated": config.get("is_authenticated", False),
        "username": config.get("username", "")
    })


# --- Devices ---

@app.route('/api/devices', methods=['GET'])
def list_devices():
    # Use global router instance with ensure_connected for session consistency
    print("Fetching device list using global router instance...")

    # Ensure we're connected before fetching devices
    if not router.ensure_connected():
        return jsonify({"error": "Failed to connect to router"}), 503

    # Note: Expired device cleanup is handled by the background thread only
    # This keeps the API response fast and avoids config race conditions
    devices = router.get_connected_devices()

    # Get whitelist using global router
    whitelist = router.get_mac_whitelist()
    whitelisted_macs = set()
    
    mac_filter_info = whitelist.get("ipv4_mac_filter_info", {})
    if isinstance(mac_filter_info, dict):
        mac_list = mac_filter_info.get("mac_filter_data", [])
        if isinstance(mac_list, list):
            for entry in mac_list:
                mac_entry = entry.get("MAC", "").upper()
                if mac_entry:
                    whitelisted_macs.add(mac_entry)
    
    # Load config for overrides and public SSID tracking
    config = load_config()
    manual_overrides = config.get("manual_overrides", {})
    public_ssid_allowed = config.get("public_ssid_allowed", {})

    # Enrich devices with whitelist status and auto-whitelist private connections
    result = []
    for i, device in enumerate(devices):
        mac = device["mac"]
        connection = device["connection"]

        # Check if this is a private connection (LAN or private SSID)
        is_private = router.is_private_connection(connection)

        # Determine time remaining (for public SSID devices)
        time_display = "--:--:--"
        expires_timestamp = None
        is_expired = False
        if mac in public_ssid_allowed:
            data = public_ssid_allowed[mac]
            expire_time = data.get("expires", 0) if isinstance(data, dict) else 0
            expires_timestamp = expire_time
            time_remaining = format_time_remaining(expire_time)
            if time_remaining:
                time_display = time_remaining
            else:
                # Device has expired - show immediately in UI
                time_display = "EXPIRED"
                is_expired = True

        # Determine status based on whitelist and overrides
        # If device is expired, show red status immediately (background thread will remove from router)
        if is_expired:
            status = "red"
        elif manual_overrides.get(mac) == "blocked":
            # Manual override takes priority - device is explicitly blocked
            # Do NOT auto-whitelist even if on private SSID
            status = "red"
        elif mac in whitelisted_macs:
            status = "green"
        elif is_private:
            # Auto-whitelist private connection devices (only if not manually blocked)
            print(f"Auto-whitelisting private connection: {mac} ({connection})")
            if router.add_mac_to_whitelist(mac):
                whitelisted_macs.add(mac)
                status = "green"
            else:
                print(f"Failed to auto-whitelist {mac}: {router.last_error}")
                status = "red"
        else:
            status = "red"

        result.append({
            "id": i + 1,
            "name": device["name"],
            "mac": mac,
            "ip": device["ip"],
            "time": time_display,
            "expires": expires_timestamp,
            "connection": connection,
            "status": status
        })
    
    return jsonify(result)


@app.route('/api/devices/connect', methods=['POST'])
def connect_device():
    """Manually add device to whitelist"""
    data = request.json
    mac = data.get("mac", "")
    connection = data.get("connection", "")

    # Ensure router is connected before making changes
    if not router.ensure_connected():
        return jsonify({"success": False, "message": "Failed to connect to router"})

    if router.add_mac_to_whitelist(mac):
        config = load_config()

        # Remove from manual overrides (for private connection devices)
        manual_overrides = config.get("manual_overrides", {})
        if mac in manual_overrides:
            del manual_overrides[mac]
            config["manual_overrides"] = manual_overrides

        # Track public SSID devices with 6-hour expiry
        if not router.is_private_connection(connection):
            public_ssid_allowed = config.get("public_ssid_allowed", {})
            expire_time = int(time.time()) + (6 * 60 * 60)  # 6 hours from now
            public_ssid_allowed[mac] = {
                "expires": expire_time,
                "connection": connection
            }
            config["public_ssid_allowed"] = public_ssid_allowed

        save_config(config)
        return jsonify({"success": True, "message": f"Added {mac} to whitelist"})
    return jsonify({"success": False, "message": router.last_error or "Failed to add device"})


@app.route('/api/devices/disconnect', methods=['POST'])
def disconnect_device():
    """Remove device from whitelist"""
    data = request.json
    mac = data.get("mac", "")
    connection = data.get("connection", "")

    # Ensure router is connected before making changes
    if not router.ensure_connected():
        return jsonify({"success": False, "message": "Failed to connect to router"})

    if router.remove_mac_from_whitelist(mac):
        config = load_config()

        # Only add blocked override for private connection devices
        # This prevents auto-whitelisting for private SSID/LAN devices
        # Public SSID devices don't need this since they aren't auto-whitelisted anyway
        if router.is_private_connection(connection):
            manual_overrides = config.get("manual_overrides", {})
            manual_overrides[mac] = "blocked"
            config["manual_overrides"] = manual_overrides

        # Remove from public_ssid_allowed if present
        public_ssid_allowed = config.get("public_ssid_allowed", {})
        if mac in public_ssid_allowed:
            del public_ssid_allowed[mac]
            config["public_ssid_allowed"] = public_ssid_allowed

        save_config(config)
        return jsonify({"success": True, "message": f"Removed {mac} from whitelist"})
    return jsonify({"success": False, "message": router.last_error or "Failed to remove device"})


# --- SSID Settings ---

@app.route('/api/ssids/available', methods=['GET'])
def get_available_ssids():
    """Get list of unique SSIDs from currently connected devices (excludes LAN ports)"""
    # Use global router instance with ensure_connected for session consistency
    if not router.ensure_connected():
        return jsonify({"ssids": [], "error": "Failed to connect to router"}), 503

    devices = router.get_connected_devices()

    # Extract unique SSIDs from connection strings, excluding LAN ports
    ssids = set()
    for device in devices:
        connection = device.get("connection", "")
        if connection and not connection.startswith("LAN Port"):
            # Extract base SSID name (remove band indicator like " (2.4G)" or " (5G)")
            ssid_name = connection
            if " (2.4G)" in ssid_name:
                ssid_name = ssid_name.replace(" (2.4G)", "")
            elif " (5G)" in ssid_name:
                ssid_name = ssid_name.replace(" (5G)", "")
            ssids.add(ssid_name)

    return jsonify({"ssids": sorted(list(ssids))})


@app.route('/api/settings/private-ssids', methods=['GET'])
def get_private_ssids():
    """Get the current list of private SSIDs"""
    config = load_config()
    private_ssids = config.get("private_ssids", [])
    return jsonify({"private_ssids": private_ssids})


@app.route('/api/settings/private-ssids', methods=['POST'])
def set_private_ssids():
    """Update the list of private SSIDs"""
    data = request.json
    private_ssids = data.get("private_ssids", [])

    # Validate input is a list of strings
    if not isinstance(private_ssids, list) or not all(isinstance(ssid, str) for ssid in private_ssids):
        return jsonify({"success": False, "message": "private_ssids must be a list of strings"})

    config = load_config()
    config["private_ssids"] = list(private_ssids)
    save_config(config)

    return jsonify({"success": True, "message": "Private SSIDs updated", "private_ssids": private_ssids})


# ============================================================
# Main
# ============================================================

def init_app():
    """Initialize application"""
    # Try to login with saved credentials
    config = load_config()
    if config.get("username") and config.get("password"):
        router.login(config["username"], config["password"])


if __name__ == '__main__':
    init_app()
    start_cleanup_thread()  # Start the background cleanup thread
    print("\n" + "="*60)
    print("  PLDT WiFi Manager - Device Management Server")
    print("="*60)
    print(f"  Access: http://192.168.1.2")
    print(f"  Local:  http://localhost")
    print("="*60)
    print(f"\n  Starting server on 0.0.0.0:{SERVER_PORT}...")

    try:
        app.run(host='0.0.0.0', port=SERVER_PORT, debug=False, threaded=True)
    except PermissionError:
        print(f"\n  Note: Port {SERVER_PORT} unavailable (needs Admin).")
        print("  Falling back to port 5000...")
        print(f"  Access: http://192.168.1.2:5000")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

