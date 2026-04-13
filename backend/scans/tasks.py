from celery import shared_task
from django.core.files import File
from django.utils import timezone

from .models import ScanJob
from .reports import generate_scan_pdf
from .scanner import run_target_scan


@shared_task(bind=True, autoretry_for=(), retry_backoff=False)
def scan_project(self, scan_job_id: int) -> dict:
    scan_job = ScanJob.objects.select_related("user").get(pk=scan_job_id)
    scan_job.status = ScanJob.Status.RUNNING
    scan_job.started_at = timezone.now()
    scan_job.error_message = ""
    scan_job.save(update_fields=["status", "started_at", "error_message", "updated_at"])

    try:
        findings = run_target_scan(scan_job.scan_type, scan_job.target_url)
        scan_job.findings = findings
        scan_job.result_summary = findings.get("summary", {})
        scan_job.status = ScanJob.Status.COMPLETED
        scan_job.finished_at = timezone.now()

        pdf_path = generate_scan_pdf(scan_job)
        with pdf_path.open("rb") as report_handle:
            scan_job.report_file.save(pdf_path.name, File(report_handle), save=False)

        scan_job.save(
            update_fields=[
                "findings",
                "result_summary",
                "status",
                "finished_at",
                "report_file",
                "updated_at",
            ]
        )
        return findings
    except Exception as exc:
        scan_job.status = ScanJob.Status.FAILED
        scan_job.error_message = str(exc)
        scan_job.finished_at = timezone.now()
        scan_job.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        raise
