from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0004_ignorerule_notificationhook_scheduledscan"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="failure_code",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="failure_context",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
