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
# Format: ip=username or hostname=username or cidr=username (one per line)
# Tailscale IPs (100.x.x.x) are auto-detected — no need to list them here.
# CIDR notation supported: 192.168.1.0/24=david
#
# Examples:
# 192.168.100.55=david
# 192.168.100.60=jesse
# 10.0.0.0/8=admin
# myhost=david
CONF
    log "Created $IP_USERS_CONF (edit to add LAN IP mappings)"
fi

# ============================================================
# Patch api/auth.py — add /api/auth/ip-detect endpoint
# with CIDR support, login-name mapping, direct token
# creation, and server-side cookie
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
for imp in ["import subprocess", "import json as _json", "import ipaddress"]:
    if imp not in content:
        content = content.replace("import base64\n", f"import base64\n{imp}\n", 1)

# Find the AuthApi class and add the ip-detect endpoint INSIDE the class.
# Insert after the __check_handler method (last method in AuthApi).
anchor = '    @exposed_http("GET", "/auth/check"'
if anchor not in content:
    anchor = '@exposed_http("GET", "/auth/check"'

if anchor in content:
    # Find the end of __check_handler method (next method or end of class)
    check_idx = content.find(anchor)
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

        def _match_ip_conf(target_key):
            """Check ip-users.conf for a matching key (IP, CIDR, or hostname)."""
            try:
                for line in open("/etc/kvmd/ip-users.conf"):
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        conf_key, conf_user = line.split("=", 1)
                        conf_key_s = conf_key.strip()
                        # CIDR match
                        if "/" in conf_key_s:
                            try:
                                if ipaddress.ip_address(target_key) in ipaddress.ip_network(conf_key_s, strict=False):
                                    return conf_user.strip()
                            except ValueError:
                                pass
                            continue
                        # Exact match (IP or hostname)
                        if conf_key_s == target_key:
                            return conf_user.strip()
            except FileNotFoundError:
                pass
            return None

        # 1) Check Tailscale API for 100.x IPs
        if ip.startswith("100."):
            try:
                result = subprocess.run(
                    ["tailscale", "whois", "--json", ip],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    info = _json.loads(result.stdout)
                    # Prefer device hostname (more specific than login)
                    node_name = info.get("Node", {}).get("Name", "").split(".")[0]
                    if node_name:
                        user = _match_ip_conf(node_name)
                    # Fall back to login name
                    if not user:
                        login = info.get("UserProfile", {}).get("LoginName", "")
                        if login and "@" in login:
                            login_user = login.split("@")[0]
                            # Check if login maps to a different kvmd username
                            mapped = _match_ip_conf(login_user)
                            user = mapped if mapped else login_user
            except Exception:
                pass

        # 2) Check static IP map (with CIDR support)
        if not user:
            user = _match_ip_conf(ip)

        if not user:
            return make_json_response({"user": None})

        # 3) Create token directly (bypass password)
        from ..auth import _Session
        auth = self.__auth
        token = auth._AuthManager__make_new_token()
        session = _Session(user=user, expire_req=0, expire_ts=0, ws_started=0)
        auth._AuthManager__sessions[token] = session

        # 4) Set auth cookie server-side
        return make_json_response({"user": user}, set_cookies={"auth_token": token})

'''
    content = content[:next_marker] + endpoint_code + content[next_marker:]
    open(path, "w").write(content)
    print("[kvmd-auth-ip] PATCHED: auth.py (ip-detect endpoint with CIDR, token, cookie)")
else:
    print("[kvmd-auth-ip] WARNING: could not find anchor in auth.py")
PYEOF
else
    log "WARNING: auth.py not found at $AUTH_PY"
fi

# ============================================================
# Patch login/main.js — auto-login when IP detected
# with loop guard and default /kvm/ redirect
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
anchor = '$("user-input").focus();'
if anchor not in content:
    print("[kvmd-auth-ip] WARNING: could not find anchor in login/main.js")
    exit(0)

auto_login = '''$("user-input").focus();

\t\t// kvmd-auth-ip: auto-detect user by IP (with retry on failure)
\t\t// Loop guard: after 3 consecutive login-page visits, show form.
\t\t// Counter is reset to 0 whenever the page is loaded > 30s after the last visit.
\t\tlet __lastTs = parseInt(sessionStorage.getItem("auto_login_last_ts") || "0");
\t\tlet __count = parseInt(sessionStorage.getItem("auto_login_count") || "0");
\t\tlet __now = Date.now();
\t\tif (__now - __lastTs > 30000) __count = 0;
\t\tsessionStorage.setItem("auto_login_last_ts", String(__now));
\t\tif (__count >= 3) {
\t\t\tsessionStorage.setItem("auto_login_count", "0");
\t\t} else {
\t\t\tsessionStorage.setItem("auto_login_count", String(__count + 1));
\t\t\t// Hide login form while detecting — prevents flash
\t\t\tdocument.body.style.visibility = "hidden";
\t\t\tlet __showLogin = function() { document.body.style.visibility = ""; };
\t\t\tlet __ipDetectAttempts = 0;
\t\t\tlet __tryIpDetect = function() {
\t\t\t\ttools.httpGet("api/auth/ip-detect", null, function(http) {
\t\t\t\t\tif (http.status === 200) {
\t\t\t\t\t\ttry {
\t\t\t\t\t\t\tlet resp = JSON.parse(http.responseText);
\t\t\t\t\t\t\tlet user = (resp.result || {}).user;
\t\t\t\t\t\t\tif (user) {
\t\t\t\t\t\t\t\tlet params = new URL(window.location.href).searchParams;
\t\t\t\t\t\t\t\tlet dest = params.get("next") || "/kvm/";
\t\t\t\t\t\t\t\twindow.location.replace(dest);
\t\t\t\t\t\t\t\treturn;
\t\t\t\t\t\t\t}
\t\t\t\t\t\t} catch(e) {}
\t\t\t\t\t}
\t\t\t\t\t// Retry up to 3 times with 2s delay (covers kvmd restart lag)
\t\t\t\t\t__ipDetectAttempts++;
\t\t\t\t\tif (__ipDetectAttempts < 3) {
\t\t\t\t\t\tsetTimeout(__tryIpDetect, 2000);
\t\t\t\t\t} else {
\t\t\t\t\t\t__showLogin();
\t\t\t\t\t}
\t\t\t\t});
\t\t\t};
\t\t\t__tryIpDetect();
\t\t}'''

content = content.replace(anchor, auto_login, 1)
open(path, "w").write(content)
print("[kvmd-auth-ip] PATCHED: login/main.js (auto-login + loop guard + /kvm/ default)")
PYEOF
else
    log "WARNING: login/main.js not found"
fi

# ============================================================
# Patch login/main.js — default redirect to /kvm/
# ============================================================
export LOGIN_JS
if [ -f "$LOGIN_JS" ]; then
    python3 <<'PYEOF'
import os

path = os.environ.get("LOGIN_JS", "")
content = open(path).read()
changed = False

# Change default redirect from "/" to "/kvm/"
if '|| "/"' in content and '|| "/kvm/"' not in content:
    content = content.replace('|| "/"', '|| "/kvm/"')
    changed = True

# Change login success redirect
if 'currentOpen("")' in content:
    content = content.replace('currentOpen("")', 'currentOpen("kvm")')
    changed = True

if changed:
    open(path, "w").write(content)
    print("[kvmd-auth-ip] PATCHED: login/main.js (default redirect → /kvm/)")
else:
    print("[kvmd-auth-ip] SKIPPED: login/main.js (redirect already set)")
PYEOF
fi

# ============================================================
# Patch session.js — logout redirect with ?next=
# ============================================================
export SESSION_JS="$WEB_DIR/share/js/kvm/session.js"
if [ -f "$SESSION_JS" ]; then
    python3 <<'PYEOF'
import os

path = os.environ.get("SESSION_JS", "")
content = open(path).read()
changed = False

# 1) Change logout redirect to include ?next= (original kvmd says tools.currentOpen("login");)
if 'tools.currentOpen("login");' in content:
    content = content.replace(
        'tools.currentOpen("login");',
        'tools.currentOpen("login?next=" + encodeURIComponent(window.location.pathname));',
        1
    )
    changed = True

# 2) Skip "Unexpected logout" modal — redirect immediately
old_modal = 'wm.error("Unexpected logout occured, please login again").then(function() {\n\t\t\t\t\ttools.currentOpen("login?next=" + encodeURIComponent(window.location.pathname));\n\t\t\t\t});'
new_direct = 'tools.currentOpen("login?next=" + encodeURIComponent(window.location.pathname));'
if old_modal in content:
    content = content.replace(old_modal, new_direct, 1)
    changed = True

if changed:
    open(path, "w").write(content)
    print("[kvmd-auth-ip] PATCHED: session.js (skip logout modal + ?next= redirect)")
else:
    print("[kvmd-auth-ip] SKIPPED: session.js (already patched or anchor not found)")
PYEOF
else
    log "WARNING: session.js not found"
fi

# ============================================================
# Patch PiKVM nginx to trust gateway proxy (realip module)
# ============================================================
NGINX_SERVER_CONF="$CONF_DIR/nginx/kvmd.ctx-server.conf"
if [ -f "$NGINX_SERVER_CONF" ]; then
    if ! grep -q 'set_real_ip_from' "$NGINX_SERVER_CONF"; then
        sed -i 's|absolute_redirect off;|# Trust gateway proxy to pass real client IP\nset_real_ip_from 192.168.100.133;\nreal_ip_header X-Real-IP;\nreal_ip_recursive on;\n\nabsolute_redirect off;|' "$NGINX_SERVER_CONF"
        log "PATCHED: nginx realip (trust gateway)"
    else
        log "SKIPPED: nginx realip (already configured)"
    fi
fi

# ============================================================
# Patch nginx to pass original URL to login page
# ============================================================
NGINX_CONF="/etc/kvmd/nginx/kvmd.ctx-server.conf"
if [ -f "$NGINX_CONF" ]; then
    if grep -q 'return 302 /login;' "$NGINX_CONF"; then
        sed -i 's|return 302 /login;|return 302 /login?next=$request_uri;|' "$NGINX_CONF"
        log "PATCHED: nginx (pass ?next= to login)"
        systemctl restart kvmd-nginx 2>/dev/null || true
    elif grep -q 'next=\$request_uri' "$NGINX_CONF"; then
        log "SKIPPED: nginx (already patched)"
    fi
fi

# ============================================================
# Clear pycache + restart kvmd
# ============================================================
find "$KVMD_DIR" -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
if systemctl is-active --quiet kvmd 2>/dev/null; then
    systemctl restart kvmd
    log "kvmd restarted"
fi

log "Done"
