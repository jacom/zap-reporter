-- สร้าง database sonarqube สำหรับ SonarQube (ใช้ user เดียวกับ zap_reporter)
SELECT 'CREATE DATABASE sonarqube OWNER zap_reporter'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sonarqube') \gexec
