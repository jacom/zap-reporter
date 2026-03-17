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

# ── สุ่ม random string (ใช้ python3 เพื่อหลีกเลี่ยงตัวอักษรพิเศษที่ทำให้ .env พัง) ──
gen_secret() {
    local len="${1:-48}"
    python3 -c "import secrets, string; \
        alphabet = string.ascii_letters + string.digits; \
        print(''.join(secrets.choice(alphabet) for _ in range($len)))"
}

# ── ตั้งหรืออัปเดตค่าใน .env ─────────────────────────────────────────────────
# ถ้า key มีอยู่แล้ว → อัปเดต, ถ้าไม่มี → append ท้ายไฟล์
set_env() {
    local key="$1" val="$2"
    if grep -q "^${key}=" .env; then
        # ใช้ python3 แทน sed เพื่อหลีกเลี่ยงปัญหา escape กับตัวอักษรพิเศษ
        python3 - "$key" "$val" << 'PYEOF'
import sys, pathlib
key, val = sys.argv[1], sys.argv[2]
p = pathlib.Path('.env')
lines = p.read_text().splitlines(keepends=True)
p.write_text(''.join(
    f'{key}={val}\n' if line.startswith(f'{key}=') else line
    for line in lines
))
PYEOF
    else
        echo "${key}=${val}" >> .env
    fi
}

# ── ตรวจจับ value ที่ corrupt (key ซ้ำใน value เดียวกัน) ─────────────────────
# เช่น: DB_PASSWORD=abc123DB_PASSWORD=xyz → corrupt
is_corrupt() {
    local key="$1"
    local val
    val=$(grep "^${key}=" .env | head -1 | cut -d'=' -f2-)
    # ถ้า value มี KEY= ซ้ำอยู่ข้างใน = corrupt
    echo "$val" | grep -q "${key}="
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

    # ── ตรวจและแก้ค่าที่ corrupt หรือยังเป็น placeholder ──────────────────────

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

    # DJANGO_ALLOWED_HOSTS — เติม IP ของเครื่องถ้ายังเป็น default
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

    # รอให้ app container พร้อม (สูงสุด 60 วินาที)
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

    _check_tool "ffuf"       "ffuf -V"
    _check_tool "testssl.sh" "testssl --version"
    _check_tool "wpscan"     "wpscan --version"
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
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo -e "  URL:      ${CYAN}http://${SERVER_IP}:8443${NC}"
    echo -e "  Username: ${CYAN}admin${NC}"
    echo -e "  Password: ${CYAN}Admin@1234!${NC}"
    echo ""
    echo -e "  ${YELLOW}กรุณาเปลี่ยน password ทันทีหลัง login ครั้งแรก${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
detect_os
install_docker
install_compose
setup_kernel
open_firewall
setup_env
start_services
verify_tools
print_summary
