from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0002_refactor_to_url_scans"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="report_content",
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
