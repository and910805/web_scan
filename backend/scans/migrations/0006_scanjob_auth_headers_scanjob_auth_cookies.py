from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0005_scanjob_failure_code_scanjob_failure_context"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="auth_cookies",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="auth_headers",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
