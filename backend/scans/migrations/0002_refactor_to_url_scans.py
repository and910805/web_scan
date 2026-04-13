from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="result_summary",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="scan_type",
            field=models.CharField(
                choices=[("web", "Web"), ("api", "API")],
                default="web",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="scanjob",
            name="target_url",
            field=models.URLField(default="https://example.com", max_length=1024),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name="scanjob",
            name="target_path",
        ),
    ]
