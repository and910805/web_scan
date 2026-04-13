from pathlib import Path

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import ScanJob


def generate_scan_pdf(scan_job: ScanJob) -> Path:
    report_dir = Path(settings.MEDIA_ROOT) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"scan-{scan_job.id}.pdf"

    doc = SimpleDocTemplate(str(report_path), pagesize=A4)
    styles = getSampleStyleSheet()
    heading = styles["Heading1"]
    normal = styles["BodyText"]
    mono = ParagraphStyle("Mono", parent=normal, fontName="Courier", fontSize=8, leading=10)

    findings = scan_job.findings or {}
    issues = findings.get("issues", [])
    summary = findings.get("summary", {})
    tls = findings.get("tls", {})
    security_headers = findings.get("security_headers", {})

    story = [
        Paragraph(f"Security Scan Report: {scan_job.project_name}", heading),
        Spacer(1, 12),
        Paragraph(f"Scan Type: {scan_job.scan_type}", normal),
        Paragraph(f"Status: {scan_job.status}", normal),
        Paragraph(f"Target URL: {scan_job.target_url}", normal),
        Paragraph(f"Issues Found: {len(issues)}", normal),
        Spacer(1, 12),
    ]

    summary_table = Table(
        [
            ["HTTP Status", summary.get("http_status", "n/a")],
            ["Critical", summary.get("critical_count", 0)],
            ["High", summary.get("high_count", 0)],
            ["Medium", summary.get("medium_count", 0)],
            ["Low", summary.get("low_count", 0)],
        ],
        hAlign="LEFT",
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 16)])
    story.extend(
        [
            Paragraph(f"TLS Status: {tls.get('status', 'n/a')}", normal),
            Paragraph(
                f"Missing Security Headers: {', '.join(security_headers.get('missing', [])) or 'None'}",
                normal,
            ),
            Spacer(1, 16),
        ]
    )

    if not issues:
        story.append(Paragraph("No obvious issues were detected by the baseline checks.", normal))
    else:
        for idx, issue in enumerate(issues, start=1):
            story.extend(
                [
                    Paragraph(f"{idx}. [{issue['severity'].upper()}] {issue['title']}", normal),
                    Paragraph(f"Category: {issue['category']}", normal),
                    Paragraph(f"Details: {issue['details']}", mono),
                    Spacer(1, 8),
                ]
            )

    doc.build(story)
    return report_path
