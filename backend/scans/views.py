from django.db.models import Count
from django.http import Http404, HttpResponse
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .decorators import deduct_credit
from .models import IgnoreRule, NotificationHook, ScanJob, ScheduledScan
from .serializers import (
    IgnoreRuleSerializer,
    NotificationHookSerializer,
    ScanJobCreateSerializer,
    ScanJobSerializer,
    ScheduledScanSerializer,
)
from .tasks import run_scheduled_scans, scan_project


class ScanJobViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ScanJob.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == "create":
            return ScanJobCreateSerializer
        return ScanJobSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._create_with_credit(request, serializer.validated_data)

    @deduct_credit(cost=1)
    def _create_with_credit(self, request, validated_data):
        scan_job = ScanJob.objects.create(
            user=request.user,
            project_name=validated_data["project_name"],
            scan_type=validated_data["scan_type"],
            target_url=validated_data["target_url"],
            auth_headers=validated_data.get("auth_headers", {}),
            auth_cookies=validated_data.get("auth_cookies", {}),
        )
        scan_project.delay(scan_job.id)
        output = ScanJobSerializer(scan_job, context=self.get_serializer_context())
        return Response(output.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        scan_job = self.get_object()
        filename = f"scan-{scan_job.id}.pdf"
        if scan_job.report_content:
            response = HttpResponse(scan_job.report_content, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response
        if not scan_job.report_file:
            raise Http404("Report not available.")
        with scan_job.report_file.open("rb") as report_handle:
            response = HttpResponse(report_handle.read(), content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="{scan_job.report_file.name.rsplit("/", 1)[-1] or filename}"'
        )
        return response

    @action(detail=False, methods=["get"])
    def trends(self, request):
        jobs = list(self.get_queryset().order_by("-created_at")[:10])
        completed_jobs = [job for job in jobs if job.status == ScanJob.Status.COMPLETED]
        latest = completed_jobs[0] if completed_jobs else None

        severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for job in completed_jobs:
            summary = job.result_summary or {}
            for severity in severity_totals:
                severity_totals[severity] += summary.get(f"{severity}_count", 0) or 0

        targets = (
            self.get_queryset()
            .values("target_url")
            .annotate(total=Count("id"))
            .order_by("-total", "target_url")[:5]
        )

        return Response(
            {
                "latest_job_id": latest.id if latest else None,
                "scan_count": self.get_queryset().count(),
                "completed_count": self.get_queryset().filter(status=ScanJob.Status.COMPLETED).count(),
                "failed_count": self.get_queryset().filter(status=ScanJob.Status.FAILED).count(),
                "severity_totals": severity_totals,
                "recent_jobs": [
                    {
                        "id": job.id,
                        "project_name": job.project_name,
                        "target_url": job.target_url,
                        "status": job.status,
                        "created_at": job.created_at,
                        "issue_count": (job.result_summary or {}).get("issue_count", 0),
                        "risk_score": (job.result_summary or {}).get("risk_score", 0),
                    }
                    for job in jobs
                ],
                "top_targets": list(targets),
            }
        )


class IgnoreRuleViewSet(viewsets.ModelViewSet):
    serializer_class = IgnoreRuleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return IgnoreRule.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ScheduledScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScheduledScanSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ScheduledScan.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        scheduled_scan = serializer.save(user=self.request.user)
        scheduled_scan.schedule_next_run()
        scheduled_scan.save(update_fields=["next_run_at", "updated_at"])

    @action(detail=False, methods=["post"])
    def run_due(self, request):
        result = run_scheduled_scans.delay()
        return Response({"task_id": result.id}, status=status.HTTP_202_ACCEPTED)


class NotificationHookViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationHookSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return NotificationHook.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
