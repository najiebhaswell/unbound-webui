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
import ssl
from datetime import datetime
from http.cookies import SimpleCookie

PORT = 38888
SSL_CERT = "/opt/unbound-webui/cert.pem"
SSL_KEY = "/opt/unbound-webui/key.pem"
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
        "password_hash": hashlib.sha256("Pa5sW0rd".encode()).hexdigest(),
        "owner": {
            "name": "",
            "email": "",
            "phone": "",
            "organization": ""
        }
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Ensure owner field exists for old configs
                if 'owner' not in config:
                    config['owner'] = default['owner']
                return config
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
        elif path == "/api/system":
            self.api_system()
        elif path.startswith("/api/dig"):
            self.api_dig(parsed.query)
        elif path == "/api/profile":
            self.api_profile_get()
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
        
        # Allow forgot-password without auth
        if path == "/api/forgot-password":
            self.api_forgot_password(body)
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
        elif path == "/api/profile":
            self.api_profile_set(body)
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
<title>Login - TrustPositif DNS</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --text-dim: #64748b;
    --primary: #3b82f6;
    --green: #22c55e;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.login-box {
    background: var(--card);
    padding: 48px 40px;
    border-radius: 16px;
    border: 1px solid var(--border);
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    width: 100%;
    max-width: 400px;
}
.logo {
    text-align: center;
    margin-bottom: 32px;
}
.logo-icon { font-size: 48px; }
.logo-text {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text);
    margin-top: 12px;
}
.logo-badge {
    display: inline-block;
    background: var(--green);
    color: white;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    margin-top: 8px;
}
input {
    width: 100%;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg);
    color: var(--text);
    font-size: 15px;
    margin-bottom: 16px;
    transition: all 0.2s;
}
input:focus {
    outline: none;
    border-color: var(--primary);
    background: white;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
}
input::placeholder { color: var(--text-dim); }
button {
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 10px;
    background: var(--primary);
    color: white;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
}
button:hover {
    background: #2563eb;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59,130,246,0.3);
}
.error {
    color: #ef4444;
    text-align: center;
    margin-bottom: 16px;
    padding: 12px;
    background: #fef2f2;
    border-radius: 8px;
    font-size: 14px;
    display: none;
}
.footer {
    text-align: center;
    margin-top: 24px;
    color: var(--text-dim);
    font-size: 13px;
}
.forgot-link {
    text-align: center;
    margin-top: 16px;
}
.forgot-link a {
    color: var(--primary);
    text-decoration: none;
    font-size: 14px;
    cursor: pointer;
}
.forgot-link a:hover { text-decoration: underline; }
.modal {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}
.modal.show { display: flex; }
.modal-box {
    background: var(--card);
    padding: 32px;
    border-radius: 16px;
    width: 100%;
    max-width: 400px;
}
.modal-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 20px;
    text-align: center;
}
.modal-info {
    background: #fef9c3;
    padding: 12px;
    border-radius: 8px;
    font-size: 13px;
    color: #854d0e;
    margin-bottom: 16px;
}
.btn-row {
    display: flex;
    gap: 12px;
    margin-top: 16px;
}
.btn-row button { flex: 1; }
.btn-gray {
    background: #94a3b8;
}
.btn-gray:hover {
    background: #64748b;
}
</style>
</head><body>
<div class="login-box">
    <div class="logo">
        <div class="logo-icon">🛡️</div>
        <div class="logo-text">TrustPositif DNS</div>
        <div class="logo-badge">SECURE LOGIN</div>
    </div>
    <div id="error" class="error"></div>
    <form onsubmit="login(event)">
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit">Sign In</button>
    </form>
    <div class="forgot-link"><a onclick="showForgotModal()">Lupa Password?</a></div>
    <div class="footer">Protected DNS Management System</div>
</div>
<div id="forgotModal" class="modal">
    <div class="modal-box">
        <div class="modal-title">Reset Password</div>
        <div id="resetNotify" class="reset-notify" style="display:none;"></div>
        <div class="modal-info">Masukkan email yang terdaftar di Owner Profile untuk verifikasi identitas.</div>
        <input type="email" id="verifyEmail" placeholder="Email terdaftar">
        <input type="password" id="resetNewPass" placeholder="Password baru">
        <input type="password" id="resetConfirmPass" placeholder="Konfirmasi password baru">
        <div class="btn-row">
            <button onclick="resetPassword()">Reset</button>
            <button class="btn-gray" onclick="hideForgotModal()">Batal</button>
        </div>
    </div>
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
function showForgotModal() { document.getElementById('forgotModal').classList.add('show'); document.getElementById('resetNotify').style.display='none'; }
function hideForgotModal() { document.getElementById('forgotModal').classList.remove('show'); }
function showResetNotify(msg, isSuccess) {
    const el = document.getElementById('resetNotify');
    el.textContent = msg;
    el.style.display = 'block';
    el.style.background = isSuccess ? '#dcfce7' : '#fee2e2';
    el.style.color = isSuccess ? '#166534' : '#dc2626';
    el.style.padding = '12px';
    el.style.borderRadius = '8px';
    el.style.marginBottom = '12px';
    el.style.fontSize = '14px';
}
async function resetPassword() {
    const email = document.getElementById('verifyEmail').value;
    const newPass = document.getElementById('resetNewPass').value;
    const confirmPass = document.getElementById('resetConfirmPass').value;
    if (!email) { showResetNotify('Masukkan email terdaftar', false); return; }
    if (newPass !== confirmPass) { showResetNotify('Password tidak cocok', false); return; }
    if (newPass.length < 4) { showResetNotify('Password minimal 4 karakter', false); return; }
    try {
        const res = await fetch('/api/forgot-password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, new_password: newPass})
        });
        const data = await res.json();
        if (data.success) {
            showResetNotify('Password berhasil direset! Silakan login.', true);
            setTimeout(() => { hideForgotModal(); }, 2000);
        } else {
            showResetNotify(data.error || 'Gagal reset password', false);
        }
    } catch (err) {
        showResetNotify('Connection error', false);
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
    
    def api_profile_get(self):
        """Get owner profile"""
        try:
            config = load_config()
            owner = config.get('owner', {
                'name': '',
                'email': '',
                'phone': '',
                'organization': ''
            })
            self.send_json(owner)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_profile_set(self, body):
        """Update owner profile"""
        try:
            data = json.loads(body)
            config = load_config()
            
            # Update owner info
            config['owner'] = {
                'name': data.get('name', '').strip()[:100],
                'email': data.get('email', '').strip()[:100],
                'phone': data.get('phone', '').strip()[:30],
                'organization': data.get('organization', '').strip()[:100]
            }
            
            save_config(config)
            self.send_json({"success": True, "message": "Profile updated"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_forgot_password(self, body):
        """Reset password with email verification"""
        try:
            data = json.loads(body)
            email = data.get('email', '').strip().lower()
            new_password = data.get('new_password', '')
            
            if not email:
                self.send_json({"error": "Email wajib diisi"}, 400)
                return
            
            if len(new_password) < 4:
                self.send_json({"error": "Password minimal 4 karakter"}, 400)
                return
            
            config = load_config()
            owner_email = config.get('owner', {}).get('email', '').strip().lower()
            
            # Verify email matches owner profile
            if not owner_email:
                self.send_json({"error": "Owner profile belum diisi. Hubungi administrator."}, 400)
                return
            
            if email != owner_email:
                self.send_json({"error": "Email tidak cocok dengan data pemilik"}, 400)
                return
            
            # Email verified, reset password
            config['password_hash'] = hash_password(new_password)
            save_config(config)
            
            self.send_json({"success": True, "message": "Password berhasil direset"})
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
            
            # Get system stats
            memory_used, memory_total = 0, 0
            disk_used, disk_total = 0, 0
            cpu_load = 0.0
            
            # Memory from /proc/meminfo
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            meminfo[parts[0].rstrip(':')] = int(parts[1])
                    memory_total = meminfo.get('MemTotal', 0) / 1024 / 1024  # GB
                    mem_available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
                    memory_used = (meminfo.get('MemTotal', 0) - mem_available) / 1024 / 1024  # GB
            except:
                pass
            
            # Disk usage
            try:
                stat = os.statvfs('/')
                disk_total = (stat.f_blocks * stat.f_frsize) / 1024 / 1024 / 1024  # GB
                disk_free = (stat.f_bfree * stat.f_frsize) / 1024 / 1024 / 1024  # GB
                disk_used = disk_total - disk_free
            except:
                pass
            
            # CPU load from /proc/loadavg
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu_load = float(f.read().split()[0])
            except:
                pass
            
            # Blocklist size from database header
            blocklist_size = 0
            try:
                db_path = "/etc/unbound/blocked_domains.db"
                if os.path.exists(db_path):
                    import struct
                    with open(db_path, "rb") as f:
                        # Header: Magic(4s) + Version(I) + Count(Q)
                        header = f.read(16)
                        if len(header) == 16:
                            magic, version, count = struct.unpack("<4sIQ", header)
                            if magic == b"PROP":
                                blocklist_size = count
            except:
                pass

            self.send_json({
                "qps": qps,
                "total_queries": total_queries,
                "uptime": int(uptime),
                "cache_hits": stats.get("total.num.cachehits", 0),
                "cache_miss": stats.get("total.num.cachemiss", 0),
                "blocked": stats.get("num.query.blocklist", 0),
                "blocklist_size": blocklist_size,
                "memory_used": round(memory_used, 1),
                "memory_total": round(memory_total, 1),
                "disk_used": round(disk_used, 1),
                "disk_total": round(disk_total, 1),
                "cpu_load": round(cpu_load, 2),
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)
    
    def api_system(self):
        """Return system stats: CPU, Memory, Disk, Network"""
        try:
            result = {}
            
            # CPU load from /proc/loadavg
            try:
                with open('/proc/loadavg', 'r') as f:
                    parts = f.read().split()
                    result['cpu'] = {
                        'load1': float(parts[0]),
                        'load5': float(parts[1]),
                        'load15': float(parts[2])
                    }
            except:
                result['cpu'] = {'load1': 0, 'load5': 0, 'load15': 0}
            
            # Memory from /proc/meminfo
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            meminfo[parts[0].rstrip(':')] = int(parts[1])
                    total_kb = meminfo.get('MemTotal', 0)
                    available_kb = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
                    used_kb = total_kb - available_kb
                    result['memory'] = {
                        'total_mb': total_kb / 1024,
                        'used_mb': used_kb / 1024,
                        'available_mb': available_kb / 1024
                    }
            except:
                result['memory'] = {'total_mb': 0, 'used_mb': 0, 'available_mb': 0}
            
            # Disk usage from os.statvfs
            try:
                stat = os.statvfs('/')
                total_bytes = stat.f_blocks * stat.f_frsize
                free_bytes = stat.f_bfree * stat.f_frsize
                used_bytes = total_bytes - free_bytes
                result['disk'] = {
                    'total_gb': total_bytes / 1024 / 1024 / 1024,
                    'used_gb': used_bytes / 1024 / 1024 / 1024,
                    'free_gb': free_bytes / 1024 / 1024 / 1024
                }
            except:
                result['disk'] = {'total_gb': 0, 'used_gb': 0, 'free_gb': 0}
            
            # Network stats from /proc/net/dev
            try:
                rx_bytes = 0
                tx_bytes = 0
                with open('/proc/net/dev', 'r') as f:
                    for line in f:
                        if ':' in line and 'lo:' not in line:
                            parts = line.split()
                            # Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
                            iface_data = line.split(':')[1].split()
                            if len(iface_data) >= 9:
                                rx_bytes += int(iface_data[0])
                                tx_bytes += int(iface_data[8])
                result['network'] = {
                    'rx_mb': rx_bytes / 1024 / 1024,
                    'tx_mb': tx_bytes / 1024 / 1024
                }
            except:
                result['network'] = {'rx_mb': 0, 'tx_mb': 0}
            
            self.send_json(result)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)
    
    def api_dig(self, query):
        """Run dig command against local DNS server"""
        try:
            parsed = urllib.parse.parse_qs(query)
            domain = parsed.get('domain', [''])[0].strip()
            record_type = parsed.get('type', ['A'])[0].upper()
            
            if not domain:
                self.send_json({'error': 'Domain is required'}, 400)
                return
            
            # Validate domain
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', domain):
                self.send_json({'error': 'Invalid domain format'}, 400)
                return
            
            # Allowed record types
            allowed_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
            if record_type not in allowed_types:
                record_type = 'A'
            
            # Run dig with @127.0.0.1
            result = subprocess.run(
                ['dig', '@127.0.0.1', domain, record_type, '+short'],
                capture_output=True, text=True, timeout=10
            )
            
            output = result.stdout.strip() or result.stderr.strip() or 'No results'
            self.send_json({'output': output, 'domain': domain, 'type': record_type})
        except subprocess.TimeoutExpired:
            self.send_json({'error': 'Query timeout'}, 504)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)
    
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

def generate_self_signed_cert():
    """Generate self-signed certificate if not exists"""
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        return True
    
    try:
        # Generate using openssl
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', SSL_KEY, '-out', SSL_CERT,
            '-days', '365', '-nodes',
            '-subj', '/CN=TrustPositif-DNS/O=WebUI/C=ID'
        ], check=True, capture_output=True)
        print(f"Generated self-signed certificate at {SSL_CERT}")
        return True
    except Exception as e:
        print(f"Failed to generate certificate: {e}")
        return False

def main():
    # Initialize config
    load_config()
    load_history()
    
    # Generate SSL certificate if needed
    generate_self_signed_cert()
    
    # Start background stats collector
    collector = threading.Thread(target=collect_stats, daemon=True)
    collector.start()
    print("Started QPS history collector (10s intervals)")
    
    # Create HTTP server
    server = http.server.HTTPServer(("0.0.0.0", PORT), UnboundHandler)
    print(f"Starting Unbound Web UI on http://0.0.0.0:{PORT}")
    
    print(f"Default login: admin / Pa5sW0rd")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSaving history and shutting down...")
        save_history()
        server.shutdown()

def reset_password(new_password):
    """Reset admin password"""
    import getpass
    
    if not new_password:
        new_password = getpass.getpass("Enter new password: ")
        confirm = getpass.getpass("Confirm password: ")
        if new_password != confirm:
            print("Passwords do not match!")
            return False
    
    config = {"username": "admin", "password_hash": hashlib.sha256(new_password.encode()).hexdigest()}
    
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        print(f"Password reset successfully!")
        print(f"Please restart unbound-webui service: sudo systemctl restart unbound-webui")
        return True
    except Exception as e:
        print(f"Failed to reset password: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--reset-password":
            new_pass = sys.argv[2] if len(sys.argv) > 2 else None
            reset_password(new_pass)
        elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("Unbound WebUI Server")
            print("")
            print("Usage:")
            print("  python3 app.py                  Start the server")
            print("  python3 app.py --reset-password [PASSWORD]")
            print("                                  Reset admin password")
            print("  python3 app.py --help           Show this help")
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for usage information")
    else:
        main()
