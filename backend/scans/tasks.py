import socket
import time
from urllib import error as urllib_error

import requests
from celery import shared_task
from django.conf import settings
from django.core.files import File
from django.utils import timezone

from .models import IgnoreRule, NotificationHook, ScanJob, ScheduledScan
from .reports import generate_scan_pdf
from .scanner import run_target_scan


@shared_task(
    bind=True,
    autoretry_for=(requests.Timeout, requests.ConnectionError, socket.timeout, TimeoutError, urllib_error.URLError),
    retry_backoff=True,
    retry_kwargs={"max_retries": 2},
)
def scan_project(self, scan_job_id: int) -> dict:
    scan_job = ScanJob.objects.select_related("user").get(pk=scan_job_id)
    scan_job.status = ScanJob.Status.RUNNING
    scan_job.started_at = timezone.now()
    scan_job.error_message = ""
    scan_job.failure_code = ""
    scan_job.failure_context = {}
    scan_job.save(update_fields=["status", "started_at", "error_message", "failure_code", "failure_context", "updated_at"])

    try:
        findings = run_target_scan(
            scan_job.scan_type,
            scan_job.target_url,
            auth_headers=scan_job.auth_headers,
            auth_cookies=scan_job.auth_cookies,
        )
        findings = _enrich_with_optional_zap(scan_job, findings)
        findings = _apply_ignore_rules(findings, scan_job)
        previous_job = _get_previous_completed_scan(scan_job)
        findings = _apply_history_comparison(findings, previous_job)
        scan_job.findings = findings
        scan_job.result_summary = findings.get("summary", {})
        scan_job.status = ScanJob.Status.COMPLETED
        scan_job.finished_at = timezone.now()

        pdf_path = generate_scan_pdf(scan_job)
        with pdf_path.open("rb") as report_handle:
            report_bytes = report_handle.read()
            report_handle.seek(0)
            scan_job.report_file.save(pdf_path.name, File(report_handle), save=False)
            scan_job.report_content = report_bytes

        scan_job.save(
            update_fields=[
                "findings",
                "result_summary",
                "status",
                "finished_at",
                "error_message",
                "failure_code",
                "failure_context",
                "report_file",
                "report_content",
                "updated_at",
            ]
        )
        _notify_hooks(scan_job)
        return findings
    except Exception as exc:
        failure = _classify_scan_failure(exc, self.request.retries)
        scan_job.status = ScanJob.Status.FAILED
        scan_job.error_message = failure["message"]
        scan_job.failure_code = failure["code"]
        scan_job.failure_context = failure["context"]
        scan_job.finished_at = timezone.now()
        scan_job.save(
            update_fields=["status", "error_message", "failure_code", "failure_context", "finished_at", "updated_at"]
        )
        raise


@shared_task(bind=True, autoretry_for=(), retry_backoff=False)
def run_scheduled_scans(self) -> dict:
    now = timezone.now()
    due_scans = list(ScheduledScan.objects.select_related("user").filter(active=True, next_run_at__lte=now))
    triggered = 0

    for scheduled_scan in due_scans:
        if scheduled_scan.user.credits < 1:
            continue

        scheduled_scan.user.credits -= 1
        scheduled_scan.user.save(update_fields=["credits"])

        scan_job = ScanJob.objects.create(
            user=scheduled_scan.user,
            project_name=scheduled_scan.project_name,
            scan_type=scheduled_scan.scan_type,
            target_url=scheduled_scan.target_url,
        )
        scan_project.delay(scan_job.id)

        scheduled_scan.last_run_at = now
        scheduled_scan.schedule_next_run(reference=now)
        scheduled_scan.save(update_fields=["last_run_at", "next_run_at", "updated_at"])
        triggered += 1

    return {"triggered": triggered}


def _get_previous_completed_scan(scan_job: ScanJob) -> ScanJob | None:
    return (
        ScanJob.objects.filter(
            user=scan_job.user,
            target_url=scan_job.target_url,
            scan_type=scan_job.scan_type,
            status=ScanJob.Status.COMPLETED,
        )
        .exclude(pk=scan_job.pk)
        .order_by("-finished_at", "-created_at")
        .first()
    )


def _apply_history_comparison(findings: dict, previous_job: ScanJob | None) -> dict:
    current_issues = findings.get("issues", [])
    previous_findings = previous_job.findings if previous_job else {}
    previous_issues = previous_findings.get("issues", [])

    previous_by_key = {_issue_key(issue): issue for issue in previous_issues}
    current_by_key = {_issue_key(issue): issue for issue in current_issues}

    for issue in current_issues:
        key = _issue_key(issue)
        issue["history_status"] = "persistent" if key in previous_by_key else "new"

    resolved_findings = [
        _history_snapshot(issue, "resolved")
        for key, issue in previous_by_key.items()
        if key not in current_by_key
    ]
    new_findings = [
        _history_snapshot(issue, "new")
        for key, issue in current_by_key.items()
        if key not in previous_by_key
    ]
    persistent_findings = [
        _history_snapshot(issue, "persistent")
        for key, issue in current_by_key.items()
        if key in previous_by_key
    ]

    history = {
        "comparison_available": previous_job is not None,
        "compared_to_job_id": previous_job.id if previous_job else None,
        "previous_finished_at": previous_job.finished_at.isoformat() if previous_job and previous_job.finished_at else None,
        "new_count": len(new_findings),
        "persistent_count": len(persistent_findings),
        "resolved_count": len(resolved_findings),
        "new_findings": new_findings[:10],
        "persistent_findings": persistent_findings[:10],
        "resolved_findings": resolved_findings[:10],
    }

    findings["history"] = history
    findings.setdefault("summary", {}).update(
        {
            "new_count": history["new_count"],
            "persistent_count": history["persistent_count"],
            "resolved_count": history["resolved_count"],
            "compared_to_job_id": history["compared_to_job_id"],
        }
    )
    return findings


def _apply_ignore_rules(findings: dict, scan_job: ScanJob) -> dict:
    issues = findings.get("issues", [])
    ignore_rules = list(IgnoreRule.objects.filter(user=scan_job.user, active=True))

    kept_issues = []
    ignored_issues = []
    for issue in issues:
        matched_rule = next((rule for rule in ignore_rules if rule.matches(issue, scan_job.target_url)), None)
        if matched_rule:
            ignored_issues.append(
                {
                    "category": issue.get("category", ""),
                    "severity": issue.get("severity", ""),
                    "title": issue.get("title", ""),
                    "ignored_by_rule_id": matched_rule.id,
                }
            )
            continue
        kept_issues.append(issue)

    findings["issues"] = kept_issues
    findings["ignored_issues"] = ignored_issues
    findings.setdefault("summary", {}).update(
        {
            "issue_count": len(kept_issues),
            "critical_count": len([item for item in kept_issues if item.get("severity") == "critical"]),
            "high_count": len([item for item in kept_issues if item.get("severity") == "high"]),
            "medium_count": len([item for item in kept_issues if item.get("severity") == "medium"]),
            "low_count": len([item for item in kept_issues if item.get("severity") == "low"]),
            "ignored_count": len(ignored_issues),
        }
    )
    return findings


def _notify_hooks(scan_job: ScanJob) -> None:
    hooks = NotificationHook.objects.filter(user=scan_job.user, active=True, on_scan_completed=True)
    payload = {
        "scan_job_id": scan_job.id,
        "project_name": scan_job.project_name,
        "scan_type": scan_job.scan_type,
        "target_url": scan_job.target_url,
        "status": scan_job.status,
        "summary": scan_job.result_summary,
    }

    for hook in hooks:
        try:
            response = requests.post(hook.target_url, json=payload, timeout=10)
            hook.last_status_code = response.status_code
            hook.last_error = ""
        except Exception as exc:
            hook.last_status_code = None
            hook.last_error = str(exc)
        hook.last_triggered_at = timezone.now()
        hook.save(update_fields=["last_status_code", "last_error", "last_triggered_at", "updated_at"])


def _enrich_with_optional_zap(scan_job: ScanJob, findings: dict) -> dict:
    if not settings.ZAP_ENABLED or not settings.ZAP_API_URL or scan_job.scan_type != ScanJob.ScanType.WEB:
        return findings

    base_url = settings.ZAP_API_URL.rstrip("/")
    params = {}
    if settings.ZAP_API_KEY:
        params["apikey"] = settings.ZAP_API_KEY

    try:
        spider_response = requests.get(
            f"{base_url}/JSON/spider/action/scan/",
            params={**params, "url": scan_job.target_url},
            timeout=15,
        )
        spider_response.raise_for_status()
        scan_id = spider_response.json().get("scan")

        if scan_id:
            for _ in range(6):
                status_response = requests.get(
                    f"{base_url}/JSON/spider/view/status/",
                    params={**params, "scanId": scan_id},
                    timeout=10,
                )
                status_response.raise_for_status()
                if status_response.json().get("status") == "100":
                    break
                time.sleep(1)

        alerts_response = requests.get(
            f"{base_url}/JSON/alert/view/alerts/",
            params={**params, "baseurl": scan_job.target_url},
            timeout=20,
        )
        alerts_response.raise_for_status()
        alerts = alerts_response.json().get("alerts", [])[:20]

        findings["issues"].extend(_map_zap_alert(alert) for alert in alerts)
        findings["zap"] = {
            "enabled": True,
            "alert_count": len(alerts),
        }
        return findings
    except Exception as exc:
        findings["zap"] = {
            "enabled": True,
            "alert_count": 0,
            "error": str(exc),
        }
        return findings


def _classify_scan_failure(exc: Exception, retries: int) -> dict:
    message = str(exc).strip() or exc.__class__.__name__
    context = {
        "exception_type": exc.__class__.__name__,
        "retries": retries,
        "retryable": False,
    }

    if isinstance(exc, (requests.Timeout, socket.timeout, TimeoutError)):
        context["retryable"] = True
        return {
            "code": "timeout",
            "message": f"Scan timed out while contacting the target. {message}",
            "context": context,
        }
    if isinstance(exc, (requests.ConnectionError, urllib_error.URLError)):
        context["retryable"] = True
        return {
            "code": "network_error",
            "message": f"Network error while contacting the target. {message}",
            "context": context,
        }
    if isinstance(exc, ValueError):
        return {
            "code": "validation_error",
            "message": f"Invalid scan request. {message}",
            "context": context,
        }
    if isinstance(exc, OSError):
        return {
            "code": "storage_error",
            "message": f"Report generation or storage failed. {message}",
            "context": context,
        }
    return {
        "code": "unexpected_error",
        "message": f"Unexpected scan failure. {message}",
        "context": context,
    }


def _map_zap_alert(alert: dict) -> dict:
    severity_map = {
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "low",
    }
    severity = severity_map.get(str(alert.get("riskcode", "")), "low")
    return {
        "category": "owasp_zap",
        "severity": severity,
        "title": alert.get("alert", "OWASP ZAP finding"),
        "details": alert.get("description", "") or alert.get("name", ""),
        "evidence": alert.get("url", ""),
        "recommendation": alert.get("solution", "") or "Review the ZAP alert and remediate the affected endpoint.",
    }


def _issue_key(issue: dict) -> str:
    parts = [
        str(issue.get("category", "")).strip().lower(),
        str(issue.get("title", "")).strip().lower(),
        str(issue.get("details", "")).strip().lower(),
    ]
    return "|".join(parts)


def _history_snapshot(issue: dict, status: str) -> dict:
    return {
        "status": status,
        "severity": issue.get("severity", "low"),
        "category": issue.get("category", ""),
        "title": issue.get("title", ""),
    }
