from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0008_alert_add_cve_ids'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='tool',
            field=__import__('django.db.models', fromlist=['CharField']).CharField(
                choices=[
                    ('zap', 'OWASP ZAP'),
                    ('trivy', 'Trivy'),
                    ('sonarqube', 'SonarQube'),
                    ('testssl', 'testssl.sh'),
                    ('wazuh', 'Wazuh'),
                    ('openvas', 'OpenVAS'),
                    ('nuclei', 'Nuclei'),
                    ('nmap', 'Nmap'),
                    ('httpx', 'httpx Probe'),
                    ('sqlmap', 'sqlmap'),
                    ('dirb', 'Dir Brute Force (ffuf)'),
                ],
                default='zap',
                max_length=20,
            ),
        ),
    ]
