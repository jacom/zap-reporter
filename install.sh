#!/bin/bash
# =============================================================================
# ZAP Reporter - Installation Script
# ติดตั้งร่วมกับ OpenVAS (Greenbone Community Edition)
#
# วิธีติดตั้ง (รันบน OpenVAS machine):
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/jacom/zap-reporter/main/install.sh)"
#
# หรือดาวน์โหลดก่อนแล้วรัน:
#
#   curl -fsSL https://raw.githubusercontent.com/jacom/zap-reporter/main/install.sh -o install.sh
#   sudo bash install.sh
# =============================================================================

set -euo pipefail

# --- สี ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
section(){ echo -e "\n${BLUE}=== $1 ===${NC}"; }

# --- ค่าเริ่มต้น ---
APP_NAME="zap-reporter"
APP_DIR="/opt/zap-reporter"
APP_USER="zap-reporter"
APP_PORT="8443"
REPO_URL="https://github.com/jacom/zap-reporter.git"
DB_NAME="zap_report"
DB_USER="zap_reporter"
DB_PASS=""   # จะ generate อัตโนมัติถ้าไม่ระบุ
VENV_DIR="${APP_DIR}/venv"
PYTHON_BIN=""

# =============================================================================
section "ตรวจสอบสิทธิ์"
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    error "กรุณารัน script นี้ด้วย root หรือ sudo"
fi

# =============================================================================
section "ตรวจสอบ OS"
# =============================================================================
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log "OS: $PRETTY_NAME"
    case "$ID" in
        debian|ubuntu|kali) : ;;
        *)
            warn "OS ที่รองรับทดสอบแล้ว: Debian/Ubuntu/Kali (OpenVAS ISO)"
            warn "OS ปัจจุบัน: $ID — อาจต้องปรับ package names เอง"
            read -rp "ต้องการดำเนินการต่อหรือไม่? [y/N]: " cont
            [[ "$cont" =~ ^[Yy]$ ]] || exit 0
            ;;
    esac
else
    warn "ไม่พบ /etc/os-release"
fi

# =============================================================================
section "ติดตั้ง System Dependencies"
# =============================================================================
log "อัปเดต package list..."
apt-get update -qq

log "ติดตั้ง packages ที่จำเป็น..."
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    postgresql \
    postgresql-client \
    nginx \
    git \
    curl \
    build-essential \
    libpq-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info \
    fonts-noto \
    fonts-noto-cjk \
    fontconfig \
    gettext-base \
    2>/dev/null

# หา python3 binary ที่ใช้ได้
for ver in python3.12 python3.11 python3.10 python3; do
    if command -v "$ver" &>/dev/null; then
        PYTHON_BIN=$(command -v "$ver")
        break
    fi
done
[[ -z "$PYTHON_BIN" ]] && error "ไม่พบ Python 3 บนระบบนี้"
log "ใช้ Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# =============================================================================
section "สร้าง System User"
# =============================================================================
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    log "สร้าง user: $APP_USER"
else
    log "User $APP_USER มีอยู่แล้ว"
fi

# =============================================================================
section "ดาวน์โหลดไฟล์แอปพลิเคชัน"
# =============================================================================
if [[ -f "$APP_DIR/manage.py" ]]; then
    log "พบไฟล์ app อยู่แล้ว — ดึงอัปเดตจาก GitHub..."
    git -C "$APP_DIR" pull --ff-only origin main || warn "git pull ล้มเหลว — ใช้ไฟล์ที่มีอยู่"
else
    log "Clone repository จาก $REPO_URL ..."
    rm -rf "$APP_DIR"
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi

mkdir -p "$APP_DIR/media" "$APP_DIR/staticfiles"
log "ดาวน์โหลดเสร็จสิ้น"

# =============================================================================
section "ตั้งค่า PostgreSQL"
# =============================================================================
# Generate password ถ้าไม่ได้กำหนด
if [[ -z "$DB_PASS" ]]; then
    set +o pipefail
    DB_PASS=$(tr -dc 'A-Za-z0-9!@#%^&*' < /dev/urandom | head -c 20)
    set -o pipefail
fi

log "ตรวจสอบว่า PostgreSQL กำลังทำงาน..."
if ! systemctl is-active --quiet postgresql; then
    systemctl start postgresql
    systemctl enable postgresql
fi

# ตรวจสอบ pg_hba.conf ว่ามี rule TCP สำหรับ zap_reporter ไหม (กรณีติดตั้งร่วมกับ OpenVAS)
PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)
if [[ -n "$PG_HBA" ]]; then
    if ! grep -q "host.*all.*${DB_USER}.*127.0.0.1" "$PG_HBA" && \
       ! grep -q "host.*all.*all.*127.0.0.1" "$PG_HBA"; then
        warn "ไม่พบ TCP rule ใน pg_hba.conf — เพิ่ม rule สำหรับ ${DB_USER}..."
        sed -i "/^# IPv4 local connections:/a host    all             ${DB_USER}      127.0.0.1\/32            scram-sha-256" "$PG_HBA"
        systemctl reload postgresql
    fi
fi

log "สร้าง database user และ database..."
# ใช้ here-doc เรียก psql ผ่าน postgres user
sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Created user ${DB_USER}';
    ELSE
        ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Updated password for ${DB_USER}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')
\gexec

GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL

log "PostgreSQL พร้อมใช้งาน (DB: $DB_NAME, User: $DB_USER)"

# =============================================================================
section "สร้างไฟล์ .env"
# =============================================================================
set +o pipefail
SECRET_KEY=$(tr -dc 'A-Za-z0-9!@#$%^&*(-_=+)' < /dev/urandom | head -c 50)
set -o pipefail

# ดึง IP ของเครื่องเพื่อใส่ใน ALLOWED_HOSTS
SERVER_IP=$(hostname -I | awk '{print $1}')

ENV_FILE="${APP_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn "พบไฟล์ .env อยู่แล้ว — สร้าง backup ก่อน"
    cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
fi

cat > "$ENV_FILE" <<EOF
# ZAP Reporter Configuration
# สร้างโดย install.sh เมื่อ $(date)

DJANGO_SECRET_KEY=${SECRET_KEY}
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=${SERVER_IP},127.0.0.1,localhost

# Database
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASS}
DB_HOST=127.0.0.1
DB_PORT=5432

# OWASP ZAP
ZAP_BASE_URL=http://127.0.0.1:8090
ZAP_API_KEY=

# Trivy
TRIVY_SERVER_URL=http://127.0.0.1:4954

# SonarQube
SONARQUBE_URL=http://127.0.0.1:9100
SONARQUBE_TOKEN=

# Wazuh
WAZUH_URL=https://127.0.0.1:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=

# OpenVAS/GVM (ติดตั้งอยู่แล้วบนเครื่องนี้)
OPENVAS_URL=http://127.0.0.1:9392
OPENVAS_USER=admin
OPENVAS_PASSWORD=

# OpenAI (optional)
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

# NVD API Key (optional)
NVD_API_KEY=

# WPScan (optional)
WPSCAN_API_TOKEN=
EOF

chmod 600 "$ENV_FILE"
log "สร้าง .env ที่ $ENV_FILE"

# =============================================================================
section "ตั้งค่า Python Virtual Environment"
# =============================================================================
log "สร้าง virtualenv..."
"$PYTHON_BIN" -m venv "$VENV_DIR"

log "ติดตั้ง Python packages จาก requirements.txt..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"
log "ติดตั้ง Python packages เสร็จสิ้น"

# =============================================================================
section "Django Setup"
# =============================================================================
cd "$APP_DIR"

log "รัน database migrations..."
"$VENV_DIR/bin/python" manage.py migrate --noinput

log "Collect static files..."
"$VENV_DIR/bin/python" manage.py collectstatic --noinput -v 0

log "สร้าง Django superuser admin..."
"$VENV_DIR/bin/python" manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@localhost', 'Admin@1234!')
    print('Superuser created: admin / Admin@1234!')
else:
    print('Superuser admin มีอยู่แล้ว')
"

# =============================================================================
section "ตั้งค่า permissions"
# =============================================================================
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod -R 755 "$APP_DIR"
chmod 600 "$ENV_FILE"
log "ตั้งค่า permissions เสร็จสิ้น"

# =============================================================================
section "สร้าง Systemd Service"
# =============================================================================
cat > /etc/systemd/system/zap-reporter.service <<EOF
[Unit]
Description=ZAP Reporter - Django Security Report Application
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=notify
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --bind unix:${APP_DIR}/gunicorn.sock \\
    --workers 3 \\
    --timeout 120 \\
    --access-logfile ${APP_DIR}/logs/access.log \\
    --error-logfile ${APP_DIR}/logs/error.log \\
    config.wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

mkdir -p "${APP_DIR}/logs"
chown -R "$APP_USER:$APP_USER" "${APP_DIR}/logs"

systemctl daemon-reload
systemctl enable zap-reporter
log "สร้าง systemd service: zap-reporter"

# =============================================================================
section "ตั้งค่า Nginx"
# =============================================================================
cat > /etc/nginx/sites-available/zap-reporter <<EOF
server {
    listen ${APP_PORT};
    server_name ${SERVER_IP} localhost;

    client_max_body_size 50M;

    location /static/ {
        alias ${APP_DIR}/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias ${APP_DIR}/media/;
    }

    location / {
        proxy_pass http://unix:${APP_DIR}/gunicorn.sock;
        proxy_set_header Host \$host:\$server_port;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }
}
EOF

# เปิดใช้งาน site
ln -sf /etc/nginx/sites-available/zap-reporter /etc/nginx/sites-enabled/zap-reporter

# ทดสอบ nginx config
if nginx -t 2>/dev/null; then
    log "Nginx config ถูกต้อง"
else
    warn "Nginx config มีปัญหา — ตรวจสอบด้วย: nginx -t"
fi

# =============================================================================
section "เริ่มต้น Services"
# =============================================================================
log "เริ่ม zap-reporter service..."
systemctl start zap-reporter

log "รีโหลด nginx..."
systemctl reload nginx || systemctl start nginx
systemctl enable nginx

# รอให้ gunicorn socket พร้อม (สูงสุด 15 วินาที)
for i in $(seq 1 15); do
    if [[ -S "${APP_DIR}/gunicorn.sock" ]]; then
        break
    fi
    sleep 1
done

if systemctl is-active --quiet zap-reporter; then
    log "zap-reporter service กำลังทำงาน"
else
    warn "zap-reporter service ไม่ได้ทำงาน — ตรวจสอบด้วย: journalctl -u zap-reporter -n 30"
fi

# =============================================================================
section "ติดตั้ง Security Tools"
# =============================================================================
CYAN='\033[0;36m'
tool_ok()  { echo -e "  ${GREEN}[มีแล้ว]${NC}  $1"; }
tool_new() { echo -e "  ${GREEN}[ติดตั้ง]${NC} $1"; }

# --- 1. OWASP ZAP ---
if [[ -f /opt/zap/zap.sh ]]; then
    tool_ok "OWASP ZAP"
else
    log "ติดตั้ง OWASP ZAP..."
    apt-get install -y --no-install-recommends default-jre-headless -qq

    set +o pipefail
    ZAP_VER=$(curl -sf "https://api.github.com/repos/zaproxy/zaproxy/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v')
    set -o pipefail
    ZAP_VER=${ZAP_VER:-2.15.0}

    curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VER}/ZAP_${ZAP_VER}_Linux.tar.gz" \
        -o /tmp/zap.tar.gz
    tar -xzf /tmp/zap.tar.gz -C /opt/
    mv "/opt/ZAP_${ZAP_VER}/" /opt/zap/
    rm -f /tmp/zap.tar.gz
    tool_new "OWASP ZAP ${ZAP_VER}"
fi

# Generate ZAP API key และอัปเดต .env
set +o pipefail
ZAP_KEY=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
set -o pipefail
sed -i "s|^ZAP_API_KEY=.*|ZAP_API_KEY=${ZAP_KEY}|" "$ENV_FILE"

# สร้าง user และ home dir สำหรับ ZAP
if ! id zap &>/dev/null; then
    useradd --system --create-home --home-dir /opt/zap-home --shell /bin/false zap
fi
mkdir -p /opt/zap-home
chown zap:zap /opt/zap-home

# Systemd service สำหรับ ZAP
if [[ ! -f /etc/systemd/system/zap.service ]]; then
    cat > /etc/systemd/system/zap.service <<EOF
[Unit]
Description=OWASP ZAP Daemon
After=network.target

[Service]
Type=simple
User=zap
Group=zap
Environment=HOME=/opt/zap-home
WorkingDirectory=/opt/zap-home
ExecStart=/opt/zap/zap.sh -daemon -host 127.0.0.1 -port 8090 \\
    -config api.key=${ZAP_KEY} \\
    -config api.addrs.addr.name=.* \\
    -config api.addrs.addr.enabled=true
Restart=on-failure
RestartSec=10
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable zap
    systemctl start zap
else
    # อัปเดต API key ใน service ที่มีอยู่แล้ว
    sed -i "s|api.key=.*|api.key=${ZAP_KEY} \\\\|" /etc/systemd/system/zap.service
    systemctl daemon-reload
    systemctl restart zap
fi

# --- 2. Trivy ---
if command -v trivy &>/dev/null; then
    tool_ok "Trivy ($(trivy --version 2>/dev/null | head -1))"
else
    log "ติดตั้ง Trivy..."
    wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor > /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list
    apt-get update -qq
    apt-get install -y trivy -qq
    tool_new "Trivy"
fi

# Trivy server service
if [[ ! -f /etc/systemd/system/trivy-server.service ]]; then
    cat > /etc/systemd/system/trivy-server.service <<EOF
[Unit]
Description=Trivy Vulnerability Scanner Server
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/trivy server --listen 127.0.0.1:4954
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable trivy-server
    systemctl start trivy-server
fi

# --- 3. WPScan ---
if command -v wpscan &>/dev/null; then
    tool_ok "WPScan ($(wpscan --version 2>/dev/null | grep 'WPScan' | head -1 | awk '{print $2}'))"
else
    log "ติดตั้ง WPScan..."
    apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev make -qq
    gem install wpscan --no-document

    # gem วาง binary ไว้ใน gem bin path — symlink ให้ใช้งานได้จากทุกที่
    WPSCAN_BIN=$(gem environment gemdir)/bin/wpscan
    if [[ -f "$WPSCAN_BIN" ]]; then
        ln -sf "$WPSCAN_BIN" /usr/local/bin/wpscan
    fi
    tool_new "WPScan"
fi

# --- 4. ffuf (Dir Brute) ---
if command -v ffuf &>/dev/null; then
    tool_ok "ffuf ($(ffuf -V 2>/dev/null | head -1))"
else
    log "ติดตั้ง ffuf..."
    set +o pipefail
    FFUF_VER=$(curl -sf "https://api.github.com/repos/ffuf/ffuf/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4)
    set -o pipefail
    FFUF_VER=${FFUF_VER:-v2.1.0}
    FFUF_URL="https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_linux_amd64.tar.gz"
    curl -fsSL "$FFUF_URL" -o /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf
    chmod +x /usr/local/bin/ffuf
    rm -f /tmp/ffuf.tar.gz
    tool_new "ffuf ${FFUF_VER}"
fi

# --- 4b. SecLists (wordlists สำหรับ ffuf) ---
if [[ -d /opt/SecLists ]]; then
    tool_ok "SecLists"
else
    log "ดาวน์โหลด SecLists wordlists..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists
    tool_new "SecLists → /opt/SecLists"
fi

# --- 5. testssl.sh ---
if command -v testssl.sh &>/dev/null || [[ -f /opt/testssl/testssl.sh ]]; then
    tool_ok "testssl.sh"
else
    log "ติดตั้ง testssl.sh..."
    apt-get install -y --no-install-recommends dnsutils openssl -qq
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
    chmod +x /opt/testssl/testssl.sh
    tool_new "testssl.sh"
fi

# --- 6. SonarQube ---
if systemctl is-active --quiet sonarqube 2>/dev/null || [[ -d /opt/sonarqube ]]; then
    tool_ok "SonarQube"
else
    log "ติดตั้ง SonarQube Community Edition..."
    apt-get install -y --no-install-recommends openjdk-17-jre-headless unzip -qq

    # SonarQube ต้องมี vm.max_map_count สูงพอ
    sysctl -w vm.max_map_count=524288 >/dev/null
    echo "vm.max_map_count=524288" >> /etc/sysctl.conf

    # สร้าง sonarqube user และ database
    if ! id sonarqube &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false sonarqube
    fi
    set +o pipefail
    SQ_PASS=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)
    set -o pipefail
    sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL 2>/dev/null
DO \$\$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sonarqube') THEN
        CREATE USER sonarqube WITH PASSWORD '${SQ_PASS}';
    END IF;
END \$\$;
SELECT 'CREATE DATABASE sonarqube OWNER sonarqube'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sonarqube')
\gexec
SQL

    # ดาวน์โหลด SonarQube
    SQ_VER="25.1.0.102122"
    curl -fsSL "https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${SQ_VER}.zip" \
        -o /tmp/sonarqube.zip
    unzip -q /tmp/sonarqube.zip -d /opt/
    mv "/opt/sonarqube-${SQ_VER}/" /opt/sonarqube/
    rm -f /tmp/sonarqube.zip

    # ตั้งค่า database
    cat >> /opt/sonarqube/conf/sonar.properties <<SQCONF
sonar.jdbc.username=sonarqube
sonar.jdbc.password=${SQ_PASS}
sonar.jdbc.url=jdbc:postgresql://127.0.0.1/sonarqube
sonar.web.host=127.0.0.1
sonar.web.port=9100
SQCONF

    chown -R sonarqube:sonarqube /opt/sonarqube

    cat > /etc/systemd/system/sonarqube.service <<EOF
[Unit]
Description=SonarQube Code Quality Scanner
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=forking
User=sonarqube
Group=sonarqube
ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop
Restart=on-failure
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sonarqube
    systemctl start sonarqube
    tool_new "SonarQube ${SQ_VER}"
fi

# =============================================================================
section "สรุปการติดตั้ง"
# =============================================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  ZAP Reporter ติดตั้งเสร็จสมบูรณ์${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  URL:          ${BLUE}http://${SERVER_IP}:${APP_PORT}/${NC}"
echo -e "  Admin user:   admin"
echo -e "  Admin pass:   Admin@1234!  ${YELLOW}(เปลี่ยนทันทีหลังเข้าสู่ระบบ)${NC}"
echo ""
echo -e "  Database:     ${DB_NAME}"
echo -e "  DB User:      ${DB_USER}"
echo -e "  DB Password:  ${DB_PASS}  ${YELLOW}(บันทึกไว้ด้วย)${NC}"
echo ""
echo -e "  App dir:      ${APP_DIR}"
echo -e "  Config:       ${APP_DIR}/.env"
echo -e "  Logs:         ${APP_DIR}/logs/"
echo ""
echo -e "${YELLOW}  ขั้นตอนต่อไป:${NC}"
echo -e "  1. แก้ไข ${APP_DIR}/.env เพื่อตั้งค่า OpenVAS password, ZAP API key ฯลฯ"
echo -e "  2. รัน: systemctl restart zap-reporter"
echo -e "  3. เข้าสู่ระบบแล้วเปลี่ยน admin password ทันที"
echo ""
echo -e "  คำสั่งที่ใช้บ่อย:"
echo -e "    systemctl status zap-reporter"
echo -e "    journalctl -u zap-reporter -f"
echo -e "    systemctl restart zap-reporter"
echo ""
echo -e "${GREEN}============================================================${NC}"
