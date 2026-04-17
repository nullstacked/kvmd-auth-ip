#!/bin/bash
set -euo pipefail

log() { echo "[kvmd-auth-ip] $*"; }

# Find kvmd install location
KVMD_DIR=$(python3 -c "import kvmd; import os; print(os.path.dirname(kvmd.__file__))" 2>/dev/null)
if [ -z "$KVMD_DIR" ]; then
    log "ERROR: Could not find kvmd installation"
    exit 1
fi
log "Found kvmd at: $KVMD_DIR"

WEB_DIR="/usr/share/kvmd/web"
CONF_DIR="/etc/kvmd"
IP_USERS_CONF="$CONF_DIR/ip-users.conf"

# Create default ip-users.conf if missing
if [ ! -f "$IP_USERS_CONF" ]; then
    cat > "$IP_USERS_CONF" <<'CONF'
# kvmd-auth-ip: Static IP to username mapping
# Format: ip=username (one per line)
# Tailscale IPs (100.x.x.x) are auto-detected — no need to list them here.
#
# Examples:
# 192.168.100.55=david
# 192.168.100.60=jesse
CONF
    log "Created $IP_USERS_CONF (edit to add LAN IP mappings)"
fi

# ============================================================
# Patch api/auth.py — add /api/auth/ip-detect endpoint
# ============================================================
export AUTH_PY="$KVMD_DIR/apps/kvmd/api/auth.py"
if [ -f "$AUTH_PY" ]; then
    python3 <<'PYEOF'
import os, re

path = os.environ.get("AUTH_PY", "")
if not path:
    print("[kvmd-auth-ip] ERROR: AUTH_PY not set"); exit(1)

content = open(path).read()

if "ip-detect" in content or "ip_detect" in content:
    print("[kvmd-auth-ip] SKIPPED: auth.py (already patched)")
    exit(0)

# Add imports at top if missing
if "import subprocess" not in content:
    content = content.replace("from typing import ", "import subprocess\nimport json as _json\n\nfrom typing import ", 1)

# Find the AuthApi class and add the ip-detect endpoint INSIDE the class.
# Insert after the __check_handler method (last method in AuthApi).
anchor = '    @exposed_http("GET", "/auth/check"'
if anchor not in content:
    anchor = '@exposed_http("GET", "/auth/check"'

if anchor in content:
    # Find the end of __check_handler method (next method or end of class)
    check_idx = content.find(anchor)
    # Find the next @exposed_http or end of class after __check_handler
    next_marker = content.find("\nasync def ", check_idx + 1)
    if next_marker < 0:
        next_marker = content.find("\ndef ", check_idx + 1)
    if next_marker < 0:
        next_marker = len(content)

    endpoint_code = '''
    @exposed_http("GET", "/auth/ip-detect", auth_required=False, allow_usc=False)
    async def __ip_detect_handler(self, req: Request) -> Response:
        ip = req.headers.get("X-Real-IP", "")
        if not ip:
            return make_json_response({"user": None})
        user = None
        # 1) Check Tailscale API for 100.x IPs
        if ip.startswith("100."):
            try:
                result = subprocess.run(
                    ["tailscale", "whois", "--json", ip],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    info = _json.loads(result.stdout)
                    # Extract login name (before @)
                    # Prefer device hostname (more specific than login)
                    node_name = info.get("Node", {}).get("Name", "").split(".")[0]
                    if node_name:
                        try:
                            for line in open("/etc/kvmd/ip-users.conf"):
                                line = line.strip()
                                if line and not line.startswith("#") and "=" in line:
                                    conf_key, conf_user = line.split("=", 1)
                                    if conf_key.strip() == node_name:
                                        user = conf_user.strip()
                                        break
                        except FileNotFoundError:
                            pass
                    # Fall back to login name for personal accounts
                    if not user:
                        login = info.get("UserProfile", {}).get("LoginName", "")
                        if login and "@" in login:
                            user = login.split("@")[0]
            except Exception:
                pass
        # 2) Check static IP map
        if not user:
            try:
                for line in open("/etc/kvmd/ip-users.conf"):
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        conf_ip, conf_user = line.split("=", 1)
                        if conf_ip.strip() == ip:
                            user = conf_user.strip()
                            break
            except FileNotFoundError:
                pass
        return make_json_response({"user": user})

'''
    content = content[:next_marker] + endpoint_code + content[next_marker:]
    open(path, "w").write(content)
    print("[kvmd-auth-ip] PATCHED: auth.py (ip-detect endpoint)")
else:
    print("[kvmd-auth-ip] WARNING: could not find anchor in auth.py")
PYEOF
else
    log "WARNING: auth.py not found at $AUTH_PY"
fi

# AUTH_PY already exported above

# ============================================================
# Patch login/main.js — auto-login when IP detected
# ============================================================
export LOGIN_JS="$WEB_DIR/share/js/login/main.js"
if [ -f "$LOGIN_JS" ]; then
    python3 <<'PYEOF'
import os

path = os.environ.get("LOGIN_JS", "")
if not path:
    print("[kvmd-auth-ip] ERROR: LOGIN_JS not set"); exit(1)

content = open(path).read()

if "ip-detect" in content:
    print("[kvmd-auth-ip] SKIPPED: login/main.js (already patched)")
    exit(0)

# Insert auto-detect call at the start of main(), after the focus() call
anchor = '$(\"user-input\").focus();'
if anchor not in content:
    print("[kvmd-auth-ip] WARNING: could not find anchor in login/main.js")
    exit(0)

auto_login = '''$("user-input").focus();

\t\t// kvmd-auth-ip: auto-detect user by IP
\t\ttools.httpGet("api/auth/ip-detect", null, function(http) {
\t\t\tif (http.status === 200) {
\t\t\t\ttry {
\t\t\t\t\tlet resp = JSON.parse(http.responseText);
\t\t\t\t\tlet user = (resp.result || {}).user;
\t\t\t\t\tif (user) {
\t\t\t\t\t\tlet body = "user=" + encodeURIComponent(user) + "&passwd=1&expire=0";
\t\t\t\t\t\ttools.httpPost("api/auth/login", null, function(lhttp) {
\t\t\t\t\t\t\tif (lhttp.status === 200) {
\t\t\t\t\t\t\t\tlet dest = document.referrer || "/";
\t\t\t\t\t\t\t\tif (dest.includes("/login")) dest = "/";
\t\t\t\t\t\t\t\twindow.location.replace(dest);
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}, body, "application/x-www-form-urlencoded");
\t\t\t\t\t}
\t\t\t\t} catch(e) {}
\t\t\t}
\t\t});'''

content = content.replace(anchor, auto_login, 1)
open(path, "w").write(content)
print("[kvmd-auth-ip] PATCHED: login/main.js (auto-login)")
PYEOF
else
    log "WARNING: login/main.js not found"
fi

# LOGIN_JS already exported above

# ============================================================
# Clear pycache + restart kvmd
# ============================================================
find "$KVMD_DIR" -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
if systemctl is-active --quiet kvmd 2>/dev/null; then
    systemctl restart kvmd
    log "kvmd restarted"
fi

log "Done"
