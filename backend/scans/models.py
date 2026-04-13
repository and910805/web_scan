from django.conf import settings
from django.db import models
from django.utils import timezone
from datetime import timedelta


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
    report_content = models.BinaryField(blank=True, null=True)
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.project_name} ({self.status})"


class IgnoreRule(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ignore_rules")
    target_url = models.URLField(max_length=1024, blank=True)
    category = models.CharField(max_length=64, blank=True)
    title_contains = models.CharField(max_length=255, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def matches(self, issue: dict, target_url: str) -> bool:
        if not self.active:
            return False
        if self.target_url and self.target_url != target_url:
            return False
        if self.category and self.category != issue.get("category", ""):
            return False
        if self.title_contains and self.title_contains.lower() not in issue.get("title", "").lower():
            return False
        return True

    def __str__(self) -> str:
        target = self.target_url or "all-targets"
        return f"{self.user.username} ignore {self.category or '*'} on {target}"


class ScheduledScan(models.Model):
    class Frequency(models.TextChoices):
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scheduled_scans")
    project_name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=16, choices=ScanJob.ScanType.choices, default=ScanJob.ScanType.WEB)
    target_url = models.URLField(max_length=1024)
    frequency = models.CharField(max_length=16, choices=Frequency.choices, default=Frequency.DAILY)
    active = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(blank=True, null=True)
    next_run_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["next_run_at", "-created_at"]

    def schedule_next_run(self, reference=None) -> None:
        reference = reference or timezone.now()
        delta_days = 1 if self.frequency == self.Frequency.DAILY else 7
        self.next_run_at = reference + timedelta(days=delta_days)

    def __str__(self) -> str:
        return f"{self.project_name} ({self.frequency})"


class NotificationHook(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_hooks")
    name = models.CharField(max_length=255)
    target_url = models.URLField(max_length=1024)
    on_scan_completed = models.BooleanField(default=True)
    active = models.BooleanField(default=True)
    last_status_code = models.PositiveIntegerField(blank=True, null=True)
    last_error = models.TextField(blank=True)
    last_triggered_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "-created_at"]

    def __str__(self) -> str:
        return f"{self.name} -> {self.target_url}"
