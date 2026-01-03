#!/usr/bin/env python3
"""
Unbound Web UI - Lightweight monitoring and management
No external dependencies - uses Python built-in http.server
With basic authentication
"""

import http.server
import json
import os
import hashlib
import secrets
import subprocess
import re
import urllib.parse
from datetime import datetime
from http.cookies import SimpleCookie

PORT = 8888
UNBOUND_CONF = "/etc/unbound/unbound.conf"
CONFIG_FILE = "/opt/unbound-webui/config.json"
HISTORY_FILE = "/opt/unbound-webui/data/history.json"

# Session storage (in-memory)
sessions = {}

# Historical QPS data (timestamp, qps, queries)
qps_history = []
MAX_HISTORY = 260000  # ~30 days at 10s intervals
last_queries = 0
last_time = 0

import threading
import time as time_module

def load_history():
    """Load history from file"""
    global qps_history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
                # Filter old data
                cutoff = time_module.time() - (30 * 86400)
                qps_history = [x for x in data if x['time'] > cutoff]
    except:
        pass

def save_history():
    """Save history to file"""
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, 'w') as f:
            json.dump(qps_history, f)
    except:
        pass

import threading
import time as time_module

def get_service_name():
    """Detect if using unbound or unbound-custom"""
    try:
        # Check if unbound-custom exists
        result = subprocess.run(
            ["systemctl", "list-unit-files", "unbound-custom.service"],
            capture_output=True, text=True
        )
        if "unbound-custom.service" in result.stdout:
            return "unbound-custom"
    except:
        pass
    return "unbound"

def collect_stats():
    """Background thread to collect QPS stats every 10 seconds"""
    global qps_history, last_queries, last_time
    while True:
        try:
            result = subprocess.run(
                ["unbound-control", "-c", "/etc/unbound/unbound.conf", "stats_noreset"],
                capture_output=True, text=True, timeout=5
            )
            stats = {}
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    try:
                        stats[key] = float(value)
                    except:
                        pass
            
            total_queries = int(stats.get("total.num.queries", 0))
            current_time = time_module.time()
            
            # Calculate real-time QPS
            if last_time > 0:
                time_diff = current_time - last_time
                query_diff = total_queries - last_queries
                
                # Handle counter reset (restart)
                if query_diff < 0:
                    query_diff = total_queries
                    
                qps = query_diff / max(time_diff, 1)
            else:
                qps = 0
            
            last_queries = total_queries
            last_time = current_time
            
            # Store in history
            qps_history.append({
                "time": current_time,
                "qps": max(0, round(qps, 2)),
                "queries": total_queries
            })
            
            # Trim history
            if len(qps_history) > MAX_HISTORY:
                qps_history = qps_history[-MAX_HISTORY:]
                
        except Exception as e:
            pass
        
        time_module.sleep(10)

def load_config():
    """Load config or create default"""
    default = {
        "username": "admin",
        "password_hash": hashlib.sha256("admin".encode()).hexdigest()
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    save_config(default)
    return default

def save_config(config):
    """Save config to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class UnboundHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/opt/unbound-webui", **kwargs)
    
    def get_session(self):
        """Get session from cookie"""
        cookie_header = self.headers.get('Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if 'session' in cookie:
            session_id = cookie['session'].value
            return sessions.get(session_id)
        return None
    
    def require_auth(self):
        """Check if request requires auth and is authenticated"""
        path = urllib.parse.urlparse(self.path).path
        # Allow login page and static assets without auth
        if path in ['/login', '/api/login'] or path.startswith('/static/'):
            return True
        return self.get_session() is not None
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        # Handle login page
        if path == "/login":
            self.serve_login()
            return
        
        # Check auth for all other pages
        if not self.require_auth():
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        
        if path == "/" or path == "/index.html":
            self.serve_dashboard()
        elif path == "/api/stats":
            self.api_stats()
        elif path == "/api/interfaces":
            self.api_interfaces()
        elif path == "/api/acl":
            self.api_acl_get()
        elif path.startswith("/api/graph"):
            self.api_graph(parsed.query)
        elif path == "/api/status":
            self.api_status()
        elif path == "/api/sinkhole":
            self.api_sinkhole_get()
        elif path == "/api/forwarders":
            self.api_forwarders_get()
        elif path == "/api/logout":
            self.api_logout()
        else:
            super().do_GET()
    
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length else ""
        
        # Allow login without auth
        if path == "/api/login":
            self.api_login(body)
            return
        
        # Check auth for all other API calls
        if not self.require_auth():
            self.send_json({"error": "Unauthorized"}, 401)
            return
        
        if path == "/api/interface":
            self.api_interface_set(body)
        elif path == "/api/acl":
            self.api_acl_set(body)
        elif path == "/api/reload":
            self.api_control("reload")
        elif path == "/api/restart":
            self.api_control("restart")
        elif path == "/api/password":
            self.api_change_password(body)
        elif path == "/api/sinkhole":
            self.api_sinkhole_set(body)
        elif path == "/api/forwarders":
            self.api_forwarders_set(body)
        elif path == "/api/forwarder/delete":
            self.api_forwarder_delete(body)
        else:
            self.send_error(404)
    
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def serve_login(self):
        html = '''<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - Unbound DNS</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 100%);
    color: #e4e4e4;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.login-box {
    background: rgba(20,30,50,0.9);
    padding: 40px;
    border-radius: 16px;
    border: 1px solid rgba(0,217,255,0.3);
    width: 100%;
    max-width: 360px;
}
h1 { text-align: center; color: #00d9ff; margin-bottom: 30px; font-size: 1.5rem; }
input {
    width: 100%;
    padding: 12px 15px;
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 8px;
    background: rgba(0,0,0,0.4);
    color: #fff;
    font-size: 1rem;
    margin-bottom: 15px;
}
input:focus { outline: none; border-color: #00d9ff; }
button {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 8px;
    background: linear-gradient(135deg, #00d9ff, #0099cc);
    color: #000;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
}
button:hover { transform: translateY(-2px); }
.error { color: #ff4444; text-align: center; margin-bottom: 15px; display: none; }
</style>
</head><body>
<div class="login-box">
    <h1>🌐 Unbound DNS</h1>
    <div id="error" class="error"></div>
    <form onsubmit="login(event)">
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</div>
<script>
async function login(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await res.json();
        if (data.success) {
            window.location.href = '/';
        } else {
            document.getElementById('error').textContent = data.error || 'Login failed';
            document.getElementById('error').style.display = 'block';
        }
    } catch (err) {
        document.getElementById('error').textContent = 'Connection error';
        document.getElementById('error').style.display = 'block';
    }
}
</script>
</body></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def api_login(self, body):
        """Handle login"""
        try:
            data = json.loads(body)
            username = data.get('username', '')
            password = data.get('password', '')
            
            config = load_config()
            
            if username == config['username'] and hash_password(password) == config['password_hash']:
                # Create session
                session_id = secrets.token_hex(32)
                sessions[session_id] = {'username': username, 'created': datetime.now().isoformat()}
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={session_id}; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode())
            else:
                self.send_json({"success": False, "error": "Invalid credentials"}, 401)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_logout(self):
        """Handle logout"""
        cookie_header = self.headers.get('Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if 'session' in cookie:
            session_id = cookie['session'].value
            sessions.pop(session_id, None)
        
        self.send_response(302)
        self.send_header('Location', '/login')
        self.send_header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.end_headers()
    
    def api_change_password(self, body):
        """Change password"""
        try:
            data = json.loads(body)
            current = data.get('current', '')
            new_pass = data.get('new', '')
            
            config = load_config()
            
            if hash_password(current) != config['password_hash']:
                self.send_json({"error": "Current password incorrect"}, 400)
                return
            
            if len(new_pass) < 4:
                self.send_json({"error": "Password too short (min 4 chars)"}, 400)
                return
            
            config['password_hash'] = hash_password(new_pass)
            save_config(config)
            
            self.send_json({"success": True, "message": "Password changed"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def serve_dashboard(self):
        try:
            with open("/opt/unbound-webui/index.html", "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "Dashboard not found")
    
    def api_stats(self):
        try:
            result = subprocess.run(
                ["unbound-control", "-c", "/etc/unbound/unbound.conf", "stats_noreset"],
                capture_output=True, text=True, timeout=5
            )
            stats = {}
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    stats[key] = float(value) if "." in value else int(value)
            
            total_queries = stats.get("total.num.queries", 0)
            uptime = stats.get("time.up", 1)
            
            # Use real-time QPS from history if available
            if qps_history:
                qps = qps_history[-1]["qps"]
            else:
                qps = 0
            
            self.send_json({
                "qps": qps,
                "total_queries": total_queries,
                "uptime": int(uptime),
                "cache_hits": stats.get("total.num.cachehits", 0),
                "cache_miss": stats.get("total.num.cachemiss", 0),
                "blocked": stats.get("num.query.blocklist", 0),
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_status(self):
        try:
            service_name = get_service_name()
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True, text=True
            )
            status = result.stdout.strip()
            
            pid_result = subprocess.run(
                ["pgrep", "-f", "/usr/sbin/unbound"],
                capture_output=True, text=True
            )
            pid = pid_result.stdout.strip().split("\n")[0] if pid_result.returncode == 0 else None
            
            self.send_json({
                "status": status,
                "pid": pid,
                "running": status == "active"
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_sinkhole_get(self):
        """Get sinkhole IP configuration"""
        try:
            ipv4 = ""
            ipv6 = ""
            
            with open(UNBOUND_CONF, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("blocklist-sinkhole:"):
                        # Extract IP from quotes
                        ip = line.split('"')[1] if '"' in line else line.split(':')[1].strip()
                        if ':' in ip:
                            ipv6 = ip
                        else:
                            ipv4 = ip
                    elif line.startswith("blocklist-sinkhole-v6:"):
                        ipv6 = line.split('"')[1] if '"' in line else line.split(':', 1)[1].strip()
            
            self.send_json({
                "ipv4": ipv4,
                "ipv6": ipv6
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_sinkhole_set(self, body):
        """Update sinkhole IP configuration"""
        try:
            data = json.loads(body)
            new_ipv4 = data.get("ipv4", "").strip()
            new_ipv6 = data.get("ipv6", "").strip()
            
            # Read current config
            with open(UNBOUND_CONF, 'r') as f:
                lines = f.readlines()
            
            # Update or add sinkhole lines
            found_v4 = False
            found_v6 = False
            new_lines = []
            
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("blocklist-sinkhole:") and not stripped.startswith("blocklist-sinkhole-v6"):
                    if new_ipv4:
                        new_lines.append(f'    blocklist-sinkhole: "{new_ipv4}"\n')
                    found_v4 = True
                elif stripped.startswith("blocklist-sinkhole-v6:"):
                    if new_ipv6:
                        new_lines.append(f'    blocklist-sinkhole-v6: "{new_ipv6}"\n')
                    found_v6 = True
                else:
                    new_lines.append(line)
            
            # Write back
            with open(UNBOUND_CONF, 'w') as f:
                f.writelines(new_lines)
            
            self.send_json({"success": True, "message": "Sinkhole IP updated"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_forwarders_get(self):
        """Get all forward-zone configurations"""
        try:
            forwarders = []
            current_zone = None
            
            with open(UNBOUND_CONF, 'r') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped == "forward-zone:":
                        if current_zone and current_zone.get("name") and current_zone.get("addrs"):
                            forwarders.append(current_zone)
                        current_zone = {"name": "", "addrs": []}
                    elif current_zone is not None:
                        if stripped.startswith("name:"):
                            name = stripped.split(":", 1)[1].strip().strip('"')
                            current_zone["name"] = name
                        elif stripped.startswith("forward-addr:"):
                            addr = stripped.split(":", 1)[1].strip()
                            current_zone["addrs"].append(addr)
                        elif stripped and not stripped.startswith("#") and not stripped.startswith("forward"):
                            # End of forward-zone block
                            if current_zone.get("name") and current_zone.get("addrs"):
                                forwarders.append(current_zone)
                            current_zone = None
                
                # Don't forget last zone
                if current_zone and current_zone.get("name") and current_zone.get("addrs"):
                    forwarders.append(current_zone)
            
            self.send_json({"forwarders": forwarders})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_forwarders_set(self, body):
        """Add or update a forward-zone"""
        try:
            data = json.loads(body)
            name = data.get("name", "").strip()
            addrs = data.get("addrs", [])  # List of resolver addresses
            
            if not name or not addrs:
                self.send_json({"error": "Name and addresses required"}, 400)
                return
            
            # Read current config
            with open(UNBOUND_CONF, 'r') as f:
                content = f.read()
            
            # Check if zone already exists
            zone_pattern = re.compile(
                r'forward-zone:\s*\n\s*name:\s*["\']?' + re.escape(name) + r'["\']?\s*\n(?:\s*forward-addr:[^\n]+\n)*',
                re.MULTILINE
            )
            
            # Build new zone config
            new_zone = "forward-zone:\n"
            new_zone += f'    name: "{name}"\n'
            for addr in addrs:
                if addr.strip():
                    new_zone += f'    forward-addr: {addr.strip()}\n'
            
            if zone_pattern.search(content):
                # Update existing zone
                content = zone_pattern.sub(new_zone, content)
            else:
                # Add new zone before the last line or at end
                if content.rstrip().endswith("}"):
                    # Has server section, add after
                    content = content.rstrip() + "\n\n" + new_zone
                else:
                    content += "\n" + new_zone
            
            with open(UNBOUND_CONF, 'w') as f:
                f.write(content)
            
            self.send_json({"success": True, "message": f"Forward zone '{name}' saved"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_forwarder_delete(self, body):
        """Delete a forward-zone"""
        try:
            data = json.loads(body)
            name = data.get("name", "").strip()
            
            if not name:
                self.send_json({"error": "Zone name required"}, 400)
                return
            
            with open(UNBOUND_CONF, 'r') as f:
                content = f.read()
            
            # Find and remove the zone
            zone_pattern = re.compile(
                r'forward-zone:\s*\n\s*name:\s*["\']?' + re.escape(name) + r'["\']?\s*\n(?:\s*forward-addr:[^\n]+\n)*\n?',
                re.MULTILINE
            )
            
            if zone_pattern.search(content):
                content = zone_pattern.sub('', content)
                # Clean up multiple newlines
                content = re.sub(r'\n{3,}', '\n\n', content)
                
                with open(UNBOUND_CONF, 'w') as f:
                    f.write(content)
                
                self.send_json({"success": True, "message": f"Forward zone '{name}' deleted"})
            else:
                self.send_json({"error": f"Zone '{name}' not found"}, 404)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_interfaces(self):
        try:
            result = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True)
            interfaces = json.loads(result.stdout)
            
            iface_list = []
            for iface in interfaces:
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                addrs = []
                for addr_info in iface.get("addr_info", []):
                    addrs.append({
                        "ip": addr_info.get("local"),
                        "prefix": addr_info.get("prefixlen"),
                        "family": addr_info.get("family")
                    })
                iface_list.append({
                    "name": name,
                    "state": iface.get("operstate", "unknown"),
                    "addresses": addrs
                })
            
            self.send_json({"interfaces": iface_list})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_interface_set(self, body):
        try:
            data = json.loads(body)
            iface = data.get("interface")
            ip = data.get("ip")
            prefix = data.get("prefix", 24)
            
            if not iface or not ip:
                self.send_json({"error": "Missing interface or ip"}, 400)
                return
            
            result = subprocess.run(
                ["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                self.send_json({"error": result.stderr}, 400)
            else:
                self.send_json({"success": True, "message": f"Added {ip}/{prefix} to {iface}"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_acl_get(self):
        try:
            acl_list = []
            with open(UNBOUND_CONF, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("access-control:"):
                        parts = line.split()
                        if len(parts) >= 3:
                            acl_list.append({"network": parts[1], "action": parts[2]})
            self.send_json({"acl": acl_list})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_acl_set(self, body):
        try:
            data = json.loads(body)
            action = data.get("action")
            network = data.get("network")
            acl_action = data.get("acl_action", "allow")
            
            if not network:
                self.send_json({"error": "Missing network"}, 400)
                return
            
            with open(UNBOUND_CONF, "r") as f:
                lines = f.readlines()
            
            new_lines = []
            acl_line = f"    access-control: {network} {acl_action}\n"
            
            if action == "add":
                in_server = False
                added = False
                for line in lines:
                    new_lines.append(line)
                    if line.strip().startswith("server:"):
                        in_server = True
                    elif in_server and line.strip().startswith("access-control:") and not added:
                        new_lines.append(acl_line)
                        added = True
                if not added:
                    new_lines.append(acl_line)
            elif action == "remove":
                for line in lines:
                    if f"access-control: {network}" not in line:
                        new_lines.append(line)
            
            with open(UNBOUND_CONF, "w") as f:
                f.writelines(new_lines)
            
            self.send_json({"success": True, "message": f"ACL {action}ed: {network}"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_control(self, action):
        try:
            if action == "reload":
                result = subprocess.run(
                    ["unbound-control", "-c", "/etc/unbound/unbound.conf", "reload"],
                    capture_output=True, text=True, timeout=10
                )
            elif action == "restart":
                service_name = get_service_name()
                result = subprocess.run(
                    ["systemctl", "restart", service_name],
                    capture_output=True, text=True, timeout=30
                )
            else:
                self.send_json({"error": "Invalid action"}, 400)
                return
            
            if result.returncode == 0:
                self.send_json({"success": True, "message": f"Unbound {action}ed"})
            else:
                self.send_json({"error": result.stderr or "Command failed"}, 500)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_graph(self, query):
        """Return historical QPS data for graphing"""
        try:
            if not qps_history:
                self.send_json({"history": [], "stats": {}})
                return
            
            # Parse period from query
            parsed = urllib.parse.parse_qs(query)
            period = parsed.get('period', ['30m'])[0]
            
            # Determine duration in seconds
            durations = {
                '30m': 1800,
                '1h': 3600,
                '12h': 43200,
                '24h': 86400,
                '7d': 604800,
                '30d': 2592000
            }
            duration = durations.get(period, 1800)
            
            cutoff = time_module.time() - duration
            
            # Filter data
            filtered = [h for h in qps_history if h['time'] > cutoff]
            if not filtered and qps_history:
                # If no data in range but history exists, show what we have if it fits
                if duration > 1800: 
                    filtered = qps_history
            
            if not filtered:
                 self.send_json({"history": [], "stats": {}})
                 return

            # Downsample if too many points (target ~300 points)
            target_points = 300
            if len(filtered) > target_points:
                step = len(filtered) / target_points
                downsampled = []
                for i in range(target_points):
                    idx = int(i * step)
                    if idx < len(filtered):
                        downsampled.append(filtered[idx])
                data = downsampled
            else:
                data = filtered
            
            # Get QPS values for filtered range
            qps_values = [h["qps"] for h in filtered] # Use full data for stats
            
            # Calculate statistics
            stats = {
                "current": qps_history[-1]["qps"],
                "min": round(min(qps_values), 2),
                "max": round(max(qps_values), 2),
                "avg": round(sum(qps_values) / len(qps_values), 2)
            }
            
            self.send_json({
                "history": data,
                "stats": stats
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

def main():
    # Initialize config
    load_config()
    load_history()
    
    # Start background stats collector
    collector = threading.Thread(target=collect_stats, daemon=True)
    collector.start()
    print("Started QPS history collector (10s intervals)")
    
    print(f"Starting Unbound Web UI on http://0.0.0.0:{PORT}")
    print(f"Default login: admin / admin")
    server = http.server.HTTPServer(("0.0.0.0", PORT), UnboundHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSaving history and shutting down...")
        save_history()
        server.shutdown()

if __name__ == "__main__":
    main()
