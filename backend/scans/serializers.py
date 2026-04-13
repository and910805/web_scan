from rest_framework import serializers

from .models import ScanJob


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
