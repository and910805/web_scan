from rest_framework import serializers

from .models import IgnoreRule, NotificationHook, ScanJob, ScheduledScan


class ScanJobCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanJob
        fields = ("id", "project_name", "scan_type", "target_url")
        read_only_fields = ("id",)

    def validate_target_url(self, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise serializers.ValidationError("Only http and https URLs are allowed.")
        return value


class ScanJobSerializer(serializers.ModelSerializer):
    credits_remaining = serializers.IntegerField(source="user.credits", read_only=True)

    class Meta:
        model = ScanJob
        fields = (
            "id",
            "project_name",
            "scan_type",
            "target_url",
            "status",
            "result_summary",
            "findings",
            "error_message",
            "report_file",
            "started_at",
            "finished_at",
            "created_at",
            "updated_at",
            "credits_remaining",
        )
        read_only_fields = fields


class IgnoreRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IgnoreRule
        fields = ("id", "target_url", "category", "title_contains", "active", "created_at", "updated_at")
        read_only_fields = ("id", "created_at", "updated_at")


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledScan
        fields = (
            "id",
            "project_name",
            "scan_type",
            "target_url",
            "frequency",
            "active",
            "last_run_at",
            "next_run_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "last_run_at", "next_run_at", "created_at", "updated_at")

    def validate_target_url(self, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise serializers.ValidationError("Only http and https URLs are allowed.")
        return value


class NotificationHookSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationHook
        fields = (
            "id",
            "name",
            "target_url",
            "on_scan_completed",
            "active",
            "last_status_code",
            "last_error",
            "last_triggered_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "last_status_code", "last_error", "last_triggered_at", "created_at", "updated_at")
