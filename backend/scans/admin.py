from django.contrib import admin

from .models import ScanJob


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "project_name", "scan_type", "user", "status", "created_at", "finished_at")
    list_filter = ("scan_type", "status", "created_at")
    search_fields = ("project_name", "target_url", "user__username")
