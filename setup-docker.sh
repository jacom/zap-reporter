#!/usr/bin/env bash
set -euo pipefail

# ── ZAP Reporter — Docker Setup Script ──────────────────────────────────────
# รองรับ: Ubuntu/Debian, AlmaLinux/Rocky Linux/RHEL
# ใช้งาน: sudo bash setup-docker.sh
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
patch()   { echo -e "${CYAN}[PATCH]${NC} $*"; }

# ── ตรวจสอบสิทธิ์ root ──────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "กรุณารันด้วย root: sudo bash $0"
fi

# ── ตรวจสอบ OS ───────────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-}"
    else
        error "ไม่สามารถตรวจสอบ OS ได้"
    fi

    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_LIKE" == *"debian"* ]]; then
        OS_FAMILY="debian"
    elif [[ "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "rhel" || "$OS_LIKE" == *"rhel"* ]]; then
        OS_FAMILY="rhel"
    else
        error "OS ไม่รองรับ: $OS_ID (รองรับ Ubuntu, Debian, AlmaLinux, Rocky Linux, RHEL)"
    fi

    info "ตรวจพบ OS: $PRETTY_NAME (family: $OS_FAMILY)"
}

# ── ติดตั้ง Docker ────────────────────────────────────────────────────────────
install_docker() {
    if command -v docker &>/dev/null; then
        ok "Docker พร้อมแล้ว: $(docker --version)"
        return
    fi

    info "ติดตั้ง Docker..."

    if [[ "$OS_FAMILY" == "debian" ]]; then
        curl -fsSL https://get.docker.com | sh
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable --now docker
    fi

    ok "Docker ติดตั้งเสร็จ: $(docker --version)"
}

# ── ตรวจสอบ Docker Compose v2 ────────────────────────────────────────────────
install_compose() {
    if docker compose version &>/dev/null; then
        ok "Docker Compose พร้อมแล้ว: $(docker compose version)"
        return
    fi

    info "ติดตั้ง Docker Compose plugin..."

    if [[ "$OS_FAMILY" == "debian" ]]; then
        apt-get install -y docker-compose-plugin
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        dnf install -y docker-compose-plugin
    fi

    ok "Docker Compose ติดตั้งเสร็จ: $(docker compose version)"
}

# ── ตั้งค่า kernel (SonarQube) ───────────────────────────────────────────────
setup_kernel() {
    local current
    current=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
    if [[ "$current" -ge 524288 ]]; then
        ok "vm.max_map_count = $current (OK)"
        return
    fi

    info "ตั้งค่า vm.max_map_count=524288 สำหรับ SonarQube..."
    if ! grep -q 'vm.max_map_count' /etc/sysctl.conf; then
        echo 'vm.max_map_count=524288' >> /etc/sysctl.conf
    else
        sed -i 's/^vm.max_map_count=.*/vm.max_map_count=524288/' /etc/sysctl.conf
    fi
    sysctl -p
    ok "vm.max_map_count ตั้งค่าเสร็จ"
}

# ── เปิด firewall port 8443 ──────────────────────────────────────────────────
open_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        info "เปิด port 8443 (ufw)..."
        ufw allow 8443/tcp
        ok "ufw: port 8443 เปิดแล้ว"
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        info "เปิด port 8443 (firewalld)..."
        firewall-cmd --permanent --add-port=8443/tcp
        firewall-cmd --reload
        ok "firewalld: port 8443 เปิดแล้ว"
    else
        warn "ไม่พบ firewall ที่ active — ข้ามขั้นตอนนี้"
    fi
}

# ── สุ่ม random string (alphanumeric เท่านั้น ไม่มีตัวอักษรพิเศษที่ทำให้ .env พัง) ──
gen_secret() {
    local len="${1:-48}"
    python3 -c "import secrets, string; \
        alphabet = string.ascii_letters + string.digits; \
        print(''.join(secrets.choice(alphabet) for _ in range($len)))"
}

# ── ตั้งหรืออัปเดตค่าใน .env (in-place เพื่อรักษา inode) ────────────────────
set_env() {
    local key="$1" val="$2"
    if grep -q "^${key}=" .env; then
        python3 - "$key" "$val" << 'PYEOF'
import sys, pathlib
key, val = sys.argv[1], sys.argv[2]
p = pathlib.Path('.env')
lines = p.read_text().splitlines(keepends=True)
content = ''.join(
    f'{key}={val}\n' if line.startswith(f'{key}=') else line
    for line in lines
)
with open(str(p), 'r+') as f:
    f.seek(0); f.write(content); f.truncate()
PYEOF
    else
        echo "${key}=${val}" >> .env
    fi
}

# ── ตรวจจับ value ที่ corrupt (key ชื่อซ้ำอยู่ใน value) ──────────────────────
is_corrupt() {
    local key="$1"
    local val
    val=$(grep "^${key}=" .env | head -1 | cut -d'=' -f2-)
    echo "$val" | grep -q "${key}="
}

# ═══════════════════════════════════════════════════════════════════════════════
# patch_code — แก้ไข source code ทั้งหมดที่จำเป็น (idempotent)
# ═══════════════════════════════════════════════════════════════════════════════
patch_code() {
    info "ตรวจสอบและแก้ไข source code..."

    # ── 1. Dockerfile — เพิ่ม security tools ──────────────────────────────────
    if ! grep -q "bsdextrautils" Dockerfile; then
        patch "Dockerfile: เพิ่ม security tools (ffuf, testssl, wpscan, dirb)"
        python3 << 'PYEOF'
import pathlib
p = pathlib.Path('Dockerfile')
txt = p.read_text()

# เพิ่ม packages
old = '    fontconfig \\\n    && fc-cache -f \\\n    && rm -rf /var/lib/apt/lists/*'
new = ('    fontconfig \\\n'
       '    curl \\\n'
       '    bsdextrautils \\\n'
       '    openssl \\\n'
       '    dnsutils \\\n'
       '    procps \\\n'
       '    dirb \\\n'
       '    ruby \\\n'
       '    ruby-dev \\\n'
       '    build-essential \\\n'
       '    && fc-cache -f \\\n'
       '    && rm -rf /var/lib/apt/lists/*')
txt = txt.replace(old, new)

# เพิ่ม tool blocks ก่อน COPY requirements.txt
tool_block = (
    '\n# ffuf — directory brute-force\n'
    'RUN FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep \'"tag_name"\' | cut -d\'"\' -f4) \\\n'
    '    && curl -sL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_linux_amd64.tar.gz" \\\n'
    '       | tar -xz -C /usr/local/bin ffuf \\\n'
    '    && chmod +x /usr/local/bin/ffuf\n'
    '\n# testssl.sh\n'
    'RUN curl -sL https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2.tar.gz \\\n'
    '       | tar -xz -C /opt \\\n'
    '    && mv /opt/testssl.sh-3.2 /opt/testssl.sh \\\n'
    '    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl\n'
    '\n# WPScan — Ruby gem\n'
    'RUN gem install wpscan --no-document\n'
    '\n'
)
txt = txt.replace('\nCOPY requirements.txt .', tool_block + 'COPY requirements.txt .')

with open('Dockerfile', 'r+') as f:
    f.seek(0); f.write(txt); f.truncate()
print('Dockerfile patched')
PYEOF
    else
        ok "Dockerfile: security tools มีอยู่แล้ว (OK)"
    fi

    # ── 2. docker-compose.yml — ZAP regex + ZAP_PORT + extra_hosts + .env mount ──
    python3 << 'PYEOF'
import pathlib, sys
p = pathlib.Path('docker-compose.yml')
txt = p.read_text()
changed = []

# ZAP: เพิ่ม regex=true
if 'api.addrs.addr(0).regex=true' not in txt:
    txt = txt.replace(
        '-config "api.addrs.addr(0).name=.*"\n',
        '-config "api.addrs.addr(0).name=.*"\n      -config "api.addrs.addr(0).regex=true"\n'
    )
    changed.append('ZAP regex=true')

# ZAP: เพิ่ม ZAP_PORT environment
if 'ZAP_PORT' not in txt:
    txt = txt.replace(
        '    user: zap\n    command: >',
        '    user: zap\n    environment:\n      ZAP_PORT: "8090"\n    command: >'
    )
    changed.append('ZAP_PORT=8090')

# app: extra_hosts
if 'host.docker.internal:host-gateway' not in txt:
    txt = txt.replace(
        '    volumes:\n      - media_data:/app/media',
        '    extra_hosts:\n      - "host.docker.internal:host-gateway"\n    volumes:\n      - media_data:/app/media'
    )
    changed.append('extra_hosts host.docker.internal')

# app: .env volume mount
if './.env:/app/.env' not in txt:
    txt = txt.replace(
        '    volumes:\n      - media_data:/app/media',
        '    volumes:\n      - ./.env:/app/.env\n      - media_data:/app/media'
    )
    changed.append('.env volume mount')

if changed:
    with open('docker-compose.yml', 'r+') as f:
        f.seek(0); f.write(txt); f.truncate()
    print('docker-compose.yml patched: ' + ', '.join(changed))
else:
    print('docker-compose.yml: OK (no changes needed)')
PYEOF

    # ── 3. dashboard/views.py ─────────────────────────────────────────────────
    python3 << 'PYEOF'
import pathlib
p = pathlib.Path('dashboard/views.py')
txt = p.read_text()
changed = []

# 3a. _read_env: fallback to os.environ
if 'Fallback: fill in any settings-page keys' not in txt:
    old = (
        '    return data\n'
        '\n'
        '\n'
        'def _write_env'
    )
    new = (
        '\n'
        '    # Fallback: fill in any settings-page keys that are set in the environment\n'
        '    # but not yet written to .env (e.g. values injected via docker-compose)\n'
        '    settings_keys = {f[\'key\'] for group in SETTINGS_FIELDS for f in group[\'fields\']}\n'
        '    for key in settings_keys:\n'
        '        if key not in data and key in os.environ:\n'
        '            data[key] = os.environ[key]\n'
        '\n'
        '    return data\n'
        '\n'
        '\n'
        'def _write_env'
    )
    txt = txt.replace(old, new)
    changed.append('_read_env fallback os.environ')

# 3b. _write_env: inode-safe write (r+ mode)
if "f.seek(0); f.writelines(lines); f.truncate()" not in txt and \
   "f.seek(0)\n        f.writelines(lines)\n        f.truncate()" not in txt:
    old = '    with open(env_path, \'w\') as f:\n        f.writelines(lines)'
    new = (
        '    # เขียน in-place เพื่อรักษา inode — ห้ามใช้ open(w) แบบสร้างไฟล์ใหม่\n'
        '    # เพราะจะทำลาย Docker bind mount\n'
        '    with open(env_path, \'r+\') as f:\n'
        '        f.seek(0)\n'
        '        f.writelines(lines)\n'
        '        f.truncate()'
    )
    txt = txt.replace(old, new)
    changed.append('_write_env inode-safe')

# 3c. _test_tool: ZAP ใช้ post_data
if "post_data.get('ZAP_BASE_URL')" not in txt:
    old = (
        "        if tool == 'zap':\n"
        "            client = ZAPClient()\n"
        "            version = client.get_version()\n"
        "            return {'tool': 'OWASP ZAP', 'ok': True, 'message': f'Connected — v{version}'}"
    )
    new = (
        "        if tool == 'zap':\n"
        "            client = ZAPClient(\n"
        "                base_url=post_data.get('ZAP_BASE_URL') or None,\n"
        "                api_key=post_data.get('ZAP_API_KEY') or None,\n"
        "            )\n"
        "            version = client.get_version()\n"
        "            return {'tool': 'OWASP ZAP', 'ok': True, 'message': f'Connected — v{version}'}"
    )
    txt = txt.replace(old, new)
    changed.append('_test_tool ZAP post_data')

# 3d. _test_tool: Trivy ใช้ post_data
if "post_data.get('TRIVY_SERVER_URL')" not in txt:
    old = (
        "        elif tool == 'trivy':\n"
        "            from scanner.trivy_scanner import TrivyClient\n"
        "            client = TrivyClient()\n"
    )
    new = (
        "        elif tool == 'trivy':\n"
        "            from scanner.trivy_scanner import TrivyClient\n"
        "            client = TrivyClient(server_url=post_data.get('TRIVY_SERVER_URL') or None)\n"
    )
    txt = txt.replace(old, new)
    changed.append('_test_tool Trivy post_data')

# 3e. _test_tool: SonarQube ใช้ post_data
if "post_data.get('SONARQUBE_URL')" not in txt:
    old = (
        "        elif tool == 'sonarqube':\n"
        "            from scanner.sonarqube_client import SonarQubeClient\n"
        "            client = SonarQubeClient()\n"
    )
    new = (
        "        elif tool == 'sonarqube':\n"
        "            from scanner.sonarqube_client import SonarQubeClient\n"
        "            client = SonarQubeClient(\n"
        "                base_url=post_data.get('SONARQUBE_URL') or None,\n"
        "                token=post_data.get('SONARQUBE_TOKEN') or None,\n"
        "            )\n"
    )
    txt = txt.replace(old, new)
    changed.append('_test_tool SonarQube post_data')

# 3f. _test_tool: Wazuh ใช้ post_data
if "post_data.get('WAZUH_URL')" not in txt:
    old = (
        "        elif tool == 'wazuh':\n"
        "            from scanner.wazuh_client import WazuhClient\n"
        "            client = WazuhClient()\n"
    )
    new = (
        "        elif tool == 'wazuh':\n"
        "            from scanner.wazuh_client import WazuhClient\n"
        "            client = WazuhClient(\n"
        "                base_url=post_data.get('WAZUH_URL') or None,\n"
        "                user=post_data.get('WAZUH_USER') or None,\n"
        "                password=post_data.get('WAZUH_PASSWORD') or None,\n"
        "            )\n"
    )
    txt = txt.replace(old, new)
    changed.append('_test_tool Wazuh post_data')

# 3g. _test_tool: OpenVAS ใช้ post_data
if "post_data.get('OPENVAS_URL')" not in txt:
    old = (
        "        elif tool == 'openvas':\n"
        "            from scanner.openvas_client import OpenVASClient\n"
        "            client = OpenVASClient()\n"
    )
    new = (
        "        elif tool == 'openvas':\n"
        "            from scanner.openvas_client import OpenVASClient\n"
        "            client = OpenVASClient(\n"
        "                base_url=post_data.get('OPENVAS_URL') or None,\n"
        "                user=post_data.get('OPENVAS_USER') or None,\n"
        "                password=post_data.get('OPENVAS_PASSWORD') or None,\n"
        "            )\n"
    )
    txt = txt.replace(old, new)
    changed.append('_test_tool OpenVAS post_data')

# 3h. Placeholder WAZUH_URL
if 'host.docker.internal:55000' not in txt:
    old = "'placeholder': 'https://127.0.0.1:55000'"
    new = "'placeholder': 'เครื่องเดียวกัน: https://host.docker.internal:55000 | เครื่องอื่น: https://192.168.x.x:55000'"
    txt = txt.replace(old, new)
    changed.append('WAZUH_URL placeholder')

# 3i. Placeholder OPENVAS_URL
if 'host.docker.internal:9390' not in txt:
    old = "'placeholder': 'http://127.0.0.1:9390'"
    new = "'placeholder': 'เครื่องเดียวกัน: http://host.docker.internal:9390 | เครื่องอื่น: http://192.168.x.x:9390'"
    txt = txt.replace(old, new)
    changed.append('OPENVAS_URL placeholder')

if changed:
    with open('dashboard/views.py', 'r+') as f:
        f.seek(0); f.write(txt); f.truncate()
    print('dashboard/views.py patched: ' + ', '.join(changed))
else:
    print('dashboard/views.py: OK (no changes needed)')
PYEOF

    # ── 4. scanner/views.py — _read_env_file + tools_status ──────────────────
    python3 << 'PYEOF'
import pathlib
p = pathlib.Path('scanner/views.py')
txt = p.read_text()
changed = []

# 4a. import pathlib
if 'import pathlib' not in txt:
    txt = txt.replace('import logging\n', 'import logging\nimport pathlib\n')
    changed.append('import pathlib')

# 4b. _read_env_file helper
if '_read_env_file' not in txt:
    insert = (
        '\n\ndef _read_env_file():\n'
        '    """อ่าน .env ล่าสุดจากไฟล์ — ใช้แทน os.environ ซึ่งถูก inject ตอน startup เท่านั้น"""\n'
        '    env = {}\n'
        '    env_path = pathlib.Path(__file__).resolve().parent.parent / \'.env\'\n'
        '    if env_path.is_file():\n'
        '        for line in env_path.read_text().splitlines():\n'
        '            line = line.strip()\n'
        '            if line and not line.startswith(\'#\') and \'=\' in line:\n'
        '                k, _, v = line.partition(\'=\')\n'
        '                env[k.strip()] = v.strip()\n'
        '    return env\n'
    )
    txt = txt.replace('\nlogger = logging.getLogger(__name__)\n',
                      '\nlogger = logging.getLogger(__name__)\n' + insert)
    changed.append('_read_env_file helper')

# 4c. tools_status: อ่านจาก .env file
if "env = _read_env_file()" not in txt:
    old = (
        'def tools_status(request):\n'
        '    """Check connectivity and version of all tools."""\n'
        '    results = {}\n'
        '\n'
        '    # ZAP\n'
        '    try:\n'
        '        zap = ZAPClient()\n'
    )
    new = (
        'def tools_status(request):\n'
        '    """Check connectivity and version of all tools."""\n'
        '    results = {}\n'
        '\n'
        '    # อ่านค่าล่าสุดจาก .env file โดยตรง\n'
        '    # (os.environ/Django settings ถูก inject ตอน startup — ไม่อัปเดตเมื่อ user save settings)\n'
        '    env = _read_env_file()\n'
        '\n'
        '    # ZAP\n'
        '    try:\n'
        '        zap = ZAPClient(\n'
        '            base_url=env.get(\'ZAP_BASE_URL\') or None,\n'
        '            api_key=env.get(\'ZAP_API_KEY\') or None,\n'
        '        )\n'
    )
    txt = txt.replace(old, new)
    changed.append('tools_status ZAP from env file')

# แก้ client อื่นใน tools_status
replacements = [
    # Trivy
    ('        trivy = TrivyClient()\n',
     '        trivy = TrivyClient(server_url=env.get(\'TRIVY_SERVER_URL\') or None)\n'),
    # SonarQube
    ('        sonar = SonarQubeClient()\n',
     '        sonar = SonarQubeClient(\n'
     '            base_url=env.get(\'SONARQUBE_URL\') or None,\n'
     '            token=env.get(\'SONARQUBE_TOKEN\') or None,\n'
     '        )\n'),
    # Wazuh
    ('        wazuh = WazuhClient()\n',
     '        wazuh = WazuhClient(\n'
     '            base_url=env.get(\'WAZUH_URL\') or None,\n'
     '            user=env.get(\'WAZUH_USER\') or None,\n'
     '            password=env.get(\'WAZUH_PASSWORD\') or None,\n'
     '        )\n'),
    # OpenVAS
    ('        openvas = OpenVASClient()\n',
     '        openvas = OpenVASClient(\n'
     '            base_url=env.get(\'OPENVAS_URL\') or None,\n'
     '            user=env.get(\'OPENVAS_USER\') or None,\n'
     '            password=env.get(\'OPENVAS_PASSWORD\') or None,\n'
     '        )\n'),
]
for old, new in replacements:
    if old in txt:
        txt = txt.replace(old, new)
        changed.append(f'tools_status {old.strip().split("=")[0].strip()} from env file')

if changed:
    with open('scanner/views.py', 'r+') as f:
        f.seek(0); f.write(txt); f.truncate()
    print('scanner/views.py patched: ' + ', '.join(changed))
else:
    print('scanner/views.py: OK (no changes needed)')
PYEOF

    # ── 5. config/urls.py — handler403 ───────────────────────────────────────
    if ! grep -q "handler403" config/urls.py; then
        patch "config/urls.py: เพิ่ม handler403"
        python3 << 'PYEOF'
import pathlib
p = pathlib.Path('config/urls.py')
txt = p.read_text()
txt = txt.replace(
    'from django.urls import path, include\n',
    'from django.urls import path, include\n\nhandler403 = \'django.views.defaults.permission_denied\'\n'
)
with open('config/urls.py', 'r+') as f:
    f.seek(0); f.write(txt); f.truncate()
print('config/urls.py patched')
PYEOF
    else
        ok "config/urls.py: handler403 มีอยู่แล้ว (OK)"
    fi

    # ── 6. dashboard/templates/403.html — custom CSRF error page ─────────────
    local tmpl_403="dashboard/templates/403.html"
    if [[ ! -f "$tmpl_403" ]]; then
        patch "สร้าง $tmpl_403 (custom CSRF error page)"
        cat > "$tmpl_403" << 'EOF'
{% extends "dashboard/base.html" %}
{% block title %}Session หมดอายุ — ZAP Reporter{% endblock %}
{% block content %}
<div class="d-flex align-items-center justify-content-center" style="min-height:60vh">
    <div class="text-center">
        <i class="bi bi-arrow-clockwise text-warning" style="font-size:4rem"></i>
        <h2 class="mt-3">Session หมดอายุ</h2>
        <p class="text-muted mb-4">
            หน้าเว็บค้างอยู่นานเกินไป กรุณารีเฟรชและลองใหม่อีกครั้ง
        </p>
        <a href="{{ request.path }}" class="btn btn-primary">
            <i class="bi bi-arrow-clockwise me-1"></i> รีเฟรชหน้านี้
        </a>
    </div>
</div>
{% endblock %}
EOF
    else
        ok "$tmpl_403: มีอยู่แล้ว (OK)"
    fi

    ok "patch_code เสร็จสมบูรณ์"
}

# ── สร้างหรือ validate .env ───────────────────────────────────────────────────
setup_env() {
    if [[ ! -f .env.example ]]; then
        error "ไม่พบ .env.example — กรุณา clone repo ก่อน"
    fi

    if [[ ! -f .env ]]; then
        cp .env.example .env
        ok "สร้าง .env จาก .env.example"
    else
        warn ".env มีอยู่แล้ว — ตรวจสอบและเติมค่าที่ขาด"
    fi

    # DB_USER — ต้องเป็น zap_reporter เสมอ
    if ! grep -q "^DB_USER=" .env; then
        set_env "DB_USER" "zap_reporter"
        ok "DB_USER: เพิ่มใหม่ → zap_reporter"
    elif [[ "$(grep "^DB_USER=" .env | cut -d'=' -f2-)" != "zap_reporter" ]]; then
        set_env "DB_USER" "zap_reporter"
        ok "DB_USER: แก้ไขเป็น zap_reporter"
    else
        ok "DB_USER: zap_reporter (OK)"
    fi

    # DB_PASSWORD — สุ่มใหม่ถ้า corrupt หรือยังเป็น placeholder
    local db_pass_val
    db_pass_val=$(grep "^DB_PASSWORD=" .env | cut -d'=' -f2-)
    if is_corrupt "DB_PASSWORD" || [[ "$db_pass_val" == "changeme"* ]] || [[ -z "$db_pass_val" ]]; then
        local db_pass
        db_pass=$(gen_secret 32)
        set_env "DB_PASSWORD" "$db_pass"
        ok "DB_PASSWORD: สร้างอัตโนมัติ"
    else
        ok "DB_PASSWORD: มีอยู่แล้ว (OK)"
    fi

    # DJANGO_SECRET_KEY — สุ่มใหม่ถ้า corrupt หรือยังเป็น placeholder
    local sk_val
    sk_val=$(grep "^DJANGO_SECRET_KEY=" .env | cut -d'=' -f2-)
    if is_corrupt "DJANGO_SECRET_KEY" || [[ "$sk_val" == "change-this"* ]] || [[ -z "$sk_val" ]]; then
        local secret_key
        secret_key=$(gen_secret 50)
        set_env "DJANGO_SECRET_KEY" "$secret_key"
        ok "DJANGO_SECRET_KEY: สร้างอัตโนมัติ"
    else
        ok "DJANGO_SECRET_KEY: มีอยู่แล้ว (OK)"
    fi

    # ZAP_API_KEY — สุ่มใหม่ถ้า corrupt หรือยังเป็น placeholder
    local zap_key_val
    zap_key_val=$(grep "^ZAP_API_KEY=" .env | cut -d'=' -f2-)
    if is_corrupt "ZAP_API_KEY" || [[ "$zap_key_val" == "your-zap"* ]] || [[ -z "$zap_key_val" ]]; then
        local zap_key
        zap_key=$(gen_secret 24)
        set_env "ZAP_API_KEY" "$zap_key"
        ok "ZAP_API_KEY: สร้างอัตโนมัติ"
    else
        ok "ZAP_API_KEY: มีอยู่แล้ว (OK)"
    fi

    # URL fields ที่ต้องมีเสมอ (internal docker service names)
    local -A REQUIRED_URLS=(
        [ZAP_BASE_URL]="http://zap:8090"
        [TRIVY_SERVER_URL]="http://trivy:4954"
        [SONARQUBE_URL]="http://sonarqube:9000"
    )
    for key in "${!REQUIRED_URLS[@]}"; do
        if ! grep -q "^${key}=" .env; then
            set_env "$key" "${REQUIRED_URLS[$key]}"
            ok "${key}: เพิ่มใหม่ → ${REQUIRED_URLS[$key]}"
        else
            ok "${key}: มีอยู่แล้ว (OK)"
        fi
    done

    # URL fields สำหรับ tools ที่อาจอยู่บน host
    # ถ้ายังเป็น 127.0.0.1 → แก้เป็น host.docker.internal (127.0.0.1 ใน container = ตัวเอง ไม่ใช่ host)
    local -A HOST_URLS=(
        [WAZUH_URL]="https://host.docker.internal:55000"
        [OPENVAS_URL]="http://host.docker.internal:9390"
    )
    for key in "${!HOST_URLS[@]}"; do
        local cur_val
        cur_val=$(grep "^${key}=" .env 2>/dev/null | cut -d'=' -f2-)
        if [[ "$cur_val" == *"127.0.0.1"* ]]; then
            set_env "$key" "${HOST_URLS[$key]}"
            warn "${key}: แก้ 127.0.0.1 → host.docker.internal"
        elif [[ -z "$cur_val" ]]; then
            set_env "$key" "${HOST_URLS[$key]}"
            ok "${key}: เพิ่มใหม่ → ${HOST_URLS[$key]}"
        else
            ok "${key}: มีอยู่แล้ว (OK)"
        fi
    done

    # DJANGO_ALLOWED_HOSTS — เติม IP จริงของเครื่อง
    local ah_val
    ah_val=$(grep "^DJANGO_ALLOWED_HOSTS=" .env | cut -d'=' -f2-)
    if [[ "$ah_val" == "127.0.0.1,localhost" ]] || [[ -z "$ah_val" ]]; then
        local server_ips
        server_ips=$(hostname -I | tr ' ' '\n' | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
        set_env "DJANGO_ALLOWED_HOSTS" "127.0.0.1,localhost,${server_ips}"
        ok "DJANGO_ALLOWED_HOSTS: อัปเดตเป็น 127.0.0.1,localhost,${server_ips}"
    else
        ok "DJANGO_ALLOWED_HOSTS: มีอยู่แล้ว (OK)"
    fi
}

# ── รัน Docker Compose ───────────────────────────────────────────────────────
start_services() {
    info "กำลัง build และเริ่ม services..."
    docker compose up -d --build
    echo ""
    ok "Services เริ่มต้นเสร็จแล้ว"
}

# ── ตรวจสอบ tools ใน app container ──────────────────────────────────────────
verify_tools() {
    info "ตรวจสอบ security tools ใน app container..."

    local retries=12
    until docker exec zap-reporter-app-1 true 2>/dev/null; do
        retries=$((retries - 1))
        [[ $retries -eq 0 ]] && warn "app container ยังไม่พร้อม — ข้ามการตรวจสอบ tools" && return
        sleep 5
    done

    local all_ok=true

    _check_tool() {
        local name="$1" cmd="$2"
        if docker exec zap-reporter-app-1 sh -c "$cmd" &>/dev/null; then
            ok "  $name"
        else
            warn "  $name — ไม่พร้อม"
            all_ok=false
        fi
    }

    _check_tool "ffuf"            "ffuf -V"
    _check_tool "testssl.sh"      "testssl --version"
    _check_tool "wpscan"          "wpscan --version"
    _check_tool "wordlist (dirb)" "test -f /usr/share/dirb/wordlists/common.txt"

    if $all_ok; then
        ok "tools ทุกตัวพร้อมใช้งาน"
    else
        warn "บาง tools อาจยังไม่พร้อม — ตรวจสอบด้วย: docker logs zap-reporter-app-1"
    fi
}

# ── แสดงผลสรุป ────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}──────────────────────────────────────────${NC}"
    echo -e "${GREEN}  ZAP Reporter พร้อมใช้งาน!${NC}"
    echo -e "${GREEN}──────────────────────────────────────────${NC}"
    echo ""
    local SERVER_IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo -e "  URL:      ${CYAN}http://${SERVER_IP}:8443${NC}"
    echo -e "  Username: ${CYAN}admin${NC}"
    echo -e "  Password: ${CYAN}Admin@1234!${NC}"
    echo ""
    echo -e "  ${YELLOW}กรุณาเปลี่ยน password ทันทีหลัง login ครั้งแรก${NC}"
    echo -e "  ${YELLOW}Wazuh/OpenVAS บนเครื่องเดียวกัน ใช้: host.docker.internal${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
detect_os
install_docker
install_compose
setup_kernel
open_firewall
patch_code
setup_env
start_services
verify_tools
print_summary
