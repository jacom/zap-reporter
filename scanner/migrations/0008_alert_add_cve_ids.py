from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0007_add_sqlmap_toolsource'),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='cve_ids',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text='CVE IDs found/related to this alert (e.g. ["CVE-2021-44228"])',
            ),
        ),
    ]
