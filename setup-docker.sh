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

# ── สร้าง .env ────────────────────────────────────────────────────────────────
setup_env() {
    if [[ -f .env ]]; then
        ok ".env มีอยู่แล้ว — ข้ามขั้นตอนนี้"
        return
    fi

    if [[ ! -f .env.example ]]; then
        error "ไม่พบ .env.example — กรุณา clone repo ก่อน"
    fi

    cp .env.example .env
    ok "สร้าง .env จาก .env.example เรียบร้อย"
    warn "กรุณาแก้ไข .env ก่อนใช้งาน: nano .env"
    warn "  - DB_PASSWORD"
    warn "  - DJANGO_SECRET_KEY"
    warn "  - DJANGO_ALLOWED_HOSTS"
    warn "  - ZAP_API_KEY"
    echo ""
    read -rp "แก้ไข .env ตอนนี้เลย? [Y/n]: " ans
    if [[ "${ans:-Y}" =~ ^[Yy]$ ]]; then
        ${EDITOR:-nano} .env
    fi
}

# ── รัน Docker Compose ───────────────────────────────────────────────────────
start_services() {
    info "กำลังเริ่ม services..."
    docker compose up -d
    echo ""
    ok "Services เริ่มต้นเสร็จแล้ว"
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
