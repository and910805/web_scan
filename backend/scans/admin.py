from django.contrib import admin

from .models import IgnoreRule, NotificationHook, ScanJob, ScheduledScan


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "project_name", "scan_type", "user", "status", "created_at", "finished_at")
    list_filter = ("scan_type", "status", "created_at")
    search_fields = ("project_name", "target_url", "user__username")
    readonly_fields = ("auth_headers", "auth_cookies", "failure_code", "failure_context")


@admin.register(IgnoreRule)
class IgnoreRuleAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "target_url", "category", "title_contains", "active", "created_at")
    list_filter = ("active", "category", "created_at")
    search_fields = ("user__username", "target_url", "title_contains")


@admin.register(ScheduledScan)
class ScheduledScanAdmin(admin.ModelAdmin):
    list_display = ("id", "project_name", "user", "scan_type", "frequency", "active", "next_run_at", "last_run_at")
    list_filter = ("active", "frequency", "scan_type")
    search_fields = ("project_name", "target_url", "user__username")


@admin.register(NotificationHook)
class NotificationHookAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "user", "active", "last_status_code", "last_triggered_at")
    list_filter = ("active", "on_scan_completed")
    search_fields = ("name", "target_url", "user__username")
