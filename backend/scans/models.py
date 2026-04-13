from django.conf import settings
from django.db import models


class ScanJob(models.Model):
    class ScanType(models.TextChoices):
        WEB = "web", "Web"
        API = "api", "API"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scan_jobs")
    project_name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=16, choices=ScanType.choices, default=ScanType.WEB)
    target_url = models.URLField(max_length=1024)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    findings = models.JSONField(default=dict, blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    report_file = models.FileField(upload_to="reports/", blank=True, null=True)
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.project_name} ({self.status})"
