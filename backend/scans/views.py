from django.http import FileResponse, Http404, HttpResponse
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .decorators import deduct_credit
from .models import ScanJob
from .serializers import ScanJobCreateSerializer, ScanJobSerializer
from .tasks import scan_project


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
        return FileResponse(
            scan_job.report_file.open("rb"),
            as_attachment=True,
            filename=scan_job.report_file.name.rsplit("/", 1)[-1] or filename,
        )
