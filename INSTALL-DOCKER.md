# ZAP Reporter — Docker Installation Guide

## Requirements

| Software | Version |
|---|---|
| Docker | 24+ |
| Docker Compose | v2 (plugin) |
| RAM | 4 GB ขึ้นไป (SonarQube ต้องการ ~2 GB) |
| Disk | 20 GB ขึ้นไป |

## Services ที่ติดตั้ง

| Service | Port | คำอธิบาย |
|---|---|---|
| ZAP Reporter (Web UI) | **8443** | Django app หลัก |
| OWASP ZAP | 8090 (internal) | Web application scanner |
| Trivy | 4954 (internal) | Container/dependency scanner |
| SonarQube | 9000 (internal) | Static code analysis |
| PostgreSQL | 5432 (internal) | Database |

---

## ขั้นตอนติดตั้ง (แบบ Script อัตโนมัติ)

```bash
git clone https://github.com/jacom/zap-reporter.git
cd zap-reporter
sudo bash setup-docker.sh
```

Script จะติดตั้ง Docker, ตั้งค่า kernel, เปิด firewall, สร้าง `.env` และรัน services ให้อัตโนมัติ

---

## ขั้นตอนติดตั้งแบบ Manual

### 1. ติดตั้ง Docker และ Docker Compose

ตรวจสอบก่อนว่ามีอยู่แล้วหรือไม่:

```bash
docker --version
docker compose version
```

ถ้ายังไม่มี ติดตั้งตาม OS:

#### Ubuntu / Debian

```bash
# ติดตั้ง Docker Engine + Compose plugin
curl -fsSL https://get.docker.com | sh

# เพิ่ม user ปัจจุบันเข้า docker group (ไม่ต้องพิมพ์ sudo ทุกครั้ง)
sudo usermod -aG docker $USER
newgrp docker
```

#### AlmaLinux / Rocky Linux / RHEL

```bash
# เพิ่ม Docker repo
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo

# ติดตั้ง Docker Engine + Compose plugin
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# เปิดใช้งานและ start service
sudo systemctl enable --now docker

# เพิ่ม user ปัจจุบันเข้า docker group
sudo usermod -aG docker $USER
newgrp docker
```

ตรวจสอบอีกครั้ง:

```bash
docker --version        # Docker version 24.x.x
docker compose version  # Docker Compose version v2.x.x
```

> **หมายเหตุ:** `docker compose` (v2, plugin) ต่างจาก `docker-compose` (v1, standalone)
> คู่มือนี้ใช้ `docker compose` (v2) เท่านั้น

---

### 2. Clone repository

```bash
git clone https://github.com/jacom/zap-reporter.git
cd zap-reporter
```

### 3. สร้างไฟล์ `.env`

```bash
cp .env.example .env
nano .env   # แก้ไข password และ API keys ที่ต้องการ
```

ค่าที่ **ต้องแก้ไข** ก่อนใช้งาน:

| Variable | คำอธิบาย |
|---|---|
| `DB_PASSWORD` | Password สำหรับ PostgreSQL |
| `DJANGO_SECRET_KEY` | Random string ยาวๆ สำหรับ Django |
| `DJANGO_ALLOWED_HOSTS` | IP/domain ของ server |
| `ZAP_API_KEY` | API Key สำหรับ OWASP ZAP |

### 4. ตั้งค่า kernel parameter สำหรับ SonarQube

> ต้องรันทุกครั้งที่ reboot หรือเพิ่มใน `/etc/sysctl.conf` เพื่อให้คงอยู่

```bash
# ตั้งค่าถาวร (แนะนำ)
echo 'vm.max_map_count=524288' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 5. เปิด firewall port 8443

#### Ubuntu (ufw)

```bash
sudo ufw allow 8443/tcp
sudo ufw reload
```

#### AlmaLinux / Rocky Linux (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### 6. เริ่มต้น services

```bash
docker compose up -d
```

รอประมาณ 2–3 นาทีให้ทุก service พร้อม ตรวจสอบสถานะ:

```bash
docker compose ps
docker compose logs -f app   # ดู log Django
```

### 7. เข้าใช้งาน

เปิด browser ไปที่:

```
http://<server-ip>:8443
```

Login ครั้งแรก:
- **Username:** `admin`
- **Password:** `Admin@1234!`

> เปลี่ยน password ทันทีหลัง login ครั้งแรก

---

## ตั้งค่า ZAP API Key

ZAP API key ถูกกำหนดใน `.env` ผ่าน `ZAP_API_KEY` ซึ่งจะถูกส่งให้ ZAP container อัตโนมัติ

ตรวจสอบว่า ZAP พร้อมใช้งาน:

```bash
curl http://localhost:8090/JSON/core/view/version/?apikey=<ZAP_API_KEY>
```

ตั้งค่าใน ZAP Reporter: **Settings → OWASP ZAP** ใส่ URL `http://zap:8090` และ API Key

---

## ตั้งค่า SonarQube Token (optional)

1. เปิด port ชั่วคราวเพื่อเข้า SonarQube UI:

```bash
# Ubuntu
sudo ufw allow 9000/tcp

# AlmaLinux
sudo firewall-cmd --temporary --add-port=9000/tcp
```

2. เปิด browser ไปที่ `http://<server-ip>:9000`
3. Login: `admin` / `admin` → เปลี่ยน password
4. ไปที่ **My Account → Security → Generate Token**
5. คัดลอก token ใส่ใน `.env`:

```bash
SONARQUBE_TOKEN=squ_xxxxxxxxxxxx
```

6. Restart app:

```bash
docker compose restart app
```

> SonarQube port 9000 ไม่ได้ expose ออกนอก Docker network โดย default
> ถ้าต้องการเปิดถาวร ให้เพิ่ม `ports: - "9000:9000"` ใน `docker-compose.yml`

---

## คำสั่งที่ใช้บ่อย

```bash
# เริ่ม / หยุด
docker compose up -d
docker compose down

# ดู logs
docker compose logs -f
docker compose logs -f app

# Restart service เดียว
docker compose restart app

# อัปเดต image ล่าสุด
docker compose pull
docker compose up -d --build

# เข้า shell ใน container
docker compose exec app bash

# Backup database
docker compose exec db pg_dump -U zap_reporter zap_report > backup.sql

# Restore database
cat backup.sql | docker compose exec -T db psql -U zap_reporter zap_report
```

---

## Uninstall

```bash
# หยุดและลบ containers (เก็บ data volumes ไว้)
docker compose down

# ลบทุกอย่างรวม data (ระวัง! ลบข้อมูลถาวร)
docker compose down -v
```
