# ZAP Reporter

ระบบจัดการและรายงานผลการทดสอบความปลอดภัย (Penetration Testing Report Platform) รองรับการสแกนด้วย OWASP ZAP, Trivy, WPScan, SonarQube, Nmap, SQLMap และอื่นๆ พร้อมออกรายงาน PDF/DOCX/Excel

## Features

- **Web Dashboard** — จัดการ scan, ดู alert, วิเคราะห์ trend
- **Multi-scanner** — OWASP ZAP, Trivy, WPScan, Nmap, SQLMap, testssl.sh, Nuclei, ffuf
- **SonarQube Integration** — Static code analysis
- **OpenVAS Integration** — Vulnerability management
- **AI Analysis** — วิเคราะห์ผลด้วย OpenAI
- **Report Generation** — PDF (WeasyPrint), DOCX (python-docx), Excel (openpyxl)
- **OWASP Mapping** — จัดกลุ่ม alert ตาม OWASP Top 10
- **CVE Enrichment** — ดึงข้อมูล CVE จาก NVD

## Deployment

| Mode | เหมาะสำหรับ |
|---|---|
| **Docker Compose** | Server ทั่วไป, VPS, ติดตั้งง่าย |
| **ISO (ZAP Appliance)** | ติดตั้งร่วม Greenbone/OpenVAS บน dedicated machine |

## ติดตั้งแบบ Docker (แนะนำ)

```bash
git clone https://github.com/jacom/zap-reporter.git
cd zap-reporter
```

สร้างไฟล์ `.env`:

```bash
cp .env.example .env
nano .env   # แก้ไข password และ API keys
```

ตั้งค่า kernel (SonarQube):

```bash
sudo sysctl -w vm.max_map_count=524288
```

เริ่มต้น:

```bash
docker compose up -d
```

เปิด browser: `http://<server-ip>:8443`
Login: `admin` / `Admin@1234!`

ดูคู่มือติดตั้งแบบละเอียด: [INSTALL-DOCKER.md](INSTALL-DOCKER.md)

## Services

| Service | Port | Image |
|---|---|---|
| ZAP Reporter | 8443 | Python 3.12 / Django 5.1 |
| OWASP ZAP | internal | ghcr.io/zaproxy/zaproxy:stable |
| Trivy | internal | aquasec/trivy:latest |
| SonarQube | internal | sonarqube:community |
| PostgreSQL | internal | postgres:16-alpine |
| Nginx | 8443 | nginx:alpine |

## Tech Stack

- **Backend:** Django 5.1, Django REST Framework
- **Database:** PostgreSQL 16
- **Web Server:** Gunicorn + Nginx
- **PDF/Report:** WeasyPrint, python-docx, openpyxl
- **Font:** Noto (รองรับภาษาไทย)
