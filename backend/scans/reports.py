from pathlib import Path
from xml.sax.saxutils import escape

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import ScanJob


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
SEVERITY_COLORS = {
    "critical": colors.HexColor("#A61B2B"),
    "high": colors.HexColor("#D64545"),
    "medium": colors.HexColor("#F59E0B"),
    "low": colors.HexColor("#2563EB"),
}
CATEGORY_LABELS = {
    "security_headers": "Security Headers",
    "tls": "TLS",
    "sensitive_path": "Sensitive Path Exposure",
    "api_surface": "API Surface",
    "cors": "CORS",
    "cookie_security": "Cookie Security",
    "information_disclosure": "Information Disclosure",
    "http_methods": "HTTP Methods",
    "transport_security": "Transport Security",
    "error_disclosure": "Error Disclosure",
    "robots_disclosure": "robots.txt Disclosure",
    "sitemap_disclosure": "sitemap.xml Disclosure",
}


def generate_scan_pdf(scan_job: ScanJob) -> Path:
    report_dir = Path(settings.MEDIA_ROOT) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"scan-{scan_job.id}.pdf"

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
    )

    findings = scan_job.findings or {}
    summary = findings.get("summary", {})
    issues = _sorted_issues(findings.get("issues", []))
    history = findings.get("history", {})
    target = findings.get("target", {})
    http_info = findings.get("http", {})
    tls = findings.get("tls", {})
    security_headers = findings.get("security_headers", {})
    styles = _build_styles()

    story = [
        _cover_banner(scan_job, summary, styles),
        Spacer(1, 7 * mm),
        Paragraph("Executive Summary", styles["section_title"]),
        Spacer(1, 2 * mm),
        _summary_cards(summary, styles),
        Spacer(1, 5 * mm),
        _history_cards(history, styles),
        Spacer(1, 5 * mm),
        _asset_overview(scan_job, target, http_info, tls, security_headers, styles),
        Spacer(1, 5 * mm),
        Paragraph("Finding Overview", styles["section_title"]),
        Spacer(1, 2 * mm),
        _findings_overview(issues, styles),
        Spacer(1, 5 * mm),
        Paragraph("Detailed Findings", styles["section_title"]),
        Spacer(1, 2 * mm),
    ]

    if not issues:
        story.append(_empty_state(styles))
    else:
        for index, issue in enumerate(issues, start=1):
            story.extend(_finding_card(index, issue, styles))

    doc.build(story, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
    return report_path


def _build_styles() -> dict:
    sample = getSampleStyleSheet()
    return {
        "kicker": ParagraphStyle(
            "Kicker",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#94A3B8"),
            alignment=TA_RIGHT,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=sample["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            textColor=colors.white,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#CBD5E1"),
        ),
        "section_title": ParagraphStyle(
            "SectionTitle",
            parent=sample["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=0,
        ),
        "table_label": ParagraphStyle(
            "TableLabel",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155"),
        ),
        "table_value": ParagraphStyle(
            "TableValue",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#0F172A"),
        ),
        "metric_label": ParagraphStyle(
            "MetricLabel",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
            alignment=TA_LEFT,
        ),
        "metric_value": ParagraphStyle(
            "MetricValue",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=20,
            textColor=colors.HexColor("#0F172A"),
        ),
        "metric_hint": ParagraphStyle(
            "MetricHint",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
        ),
        "body": ParagraphStyle(
            "Body",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        ),
        "small": ParagraphStyle(
            "Small",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=sample["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=colors.HexColor("#0F172A"),
        ),
        "finding_meta": ParagraphStyle(
            "FindingMeta",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
        ),
        "finding_block_label": ParagraphStyle(
            "FindingBlockLabel",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1E293B"),
        ),
        "finding_block_body": ParagraphStyle(
            "FindingBlockBody",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155"),
        ),
        "empty": ParagraphStyle(
            "Empty",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#475569"),
        ),
    }


def _cover_banner(scan_job: ScanJob, summary: dict, styles: dict) -> Table:
    status = _title_case(scan_job.status)
    score = summary.get("risk_score", 0)
    total_findings = summary.get("issue_count", 0)
    content = Table(
        [
            [Paragraph("WEAKSCAN ASSESSMENT REPORT", styles["kicker"])],
            [Paragraph(escape(scan_job.project_name), styles["cover_title"])],
            [
                Paragraph(
                    escape(
                        f"Target: {scan_job.target_url} | Scan Type: {scan_job.scan_type.upper()} | Status: {status}"
                    ),
                    styles["cover_subtitle"],
                )
            ],
            [
                Paragraph(
                    escape(f"Risk Score {score} | Findings {total_findings}"),
                    styles["cover_subtitle"],
                )
            ],
        ],
        colWidths=[182 * mm],
    )
    content.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#1E293B")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    return content


def _summary_cards(summary: dict, styles: dict) -> Table:
    cards = [
        _metric_card("Risk Score", summary.get("risk_score", 0), "Weighted severity score", styles),
        _metric_card("Total Findings", summary.get("issue_count", 0), "All severities combined", styles),
        _metric_card("Critical", summary.get("critical_count", 0), "Immediate remediation", styles),
        _metric_card("High", summary.get("high_count", 0), "Priority remediation", styles),
        _metric_card("Medium", summary.get("medium_count", 0), "Planned remediation", styles),
        _metric_card("Low", summary.get("low_count", 0), "Hardening opportunity", styles),
    ]

    table = Table(
        [cards[:3], cards[3:]],
        colWidths=[59 * mm, 59 * mm, 59 * mm],
        rowHeights=[22 * mm, 22 * mm],
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return table


def _history_cards(history: dict, styles: dict) -> Table:
    baseline = "Compared to previous completed scan" if history.get("comparison_available") else "No earlier baseline yet"
    cards = [
        _metric_card("New Findings", history.get("new_count", 0), baseline, styles),
        _metric_card("Persistent", history.get("persistent_count", 0), "Still present after comparison", styles),
        _metric_card("Resolved", history.get("resolved_count", 0), "Present before, absent now", styles),
    ]
    table = Table([cards], colWidths=[59 * mm, 59 * mm, 59 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return table


def _metric_card(label: str, value: int, hint: str, styles: dict) -> Table:
    table = Table(
        [
            [Paragraph(label, styles["metric_label"])],
            [Paragraph(str(value), styles["metric_value"])],
            [Paragraph(hint, styles["metric_hint"])],
        ],
        colWidths=[55 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _asset_overview(scan_job: ScanJob, target: dict, http_info: dict, tls: dict, security_headers: dict, styles: dict) -> Table:
    rows = [
        ("Project Name", scan_job.project_name),
        ("Target URL", scan_job.target_url),
        ("Scan Type", scan_job.scan_type.upper()),
        ("Resolved IP", target.get("resolved_ip") or "Unavailable"),
        ("HTTP Status", str(http_info.get("status_code", "n/a"))),
        ("Server Banner", http_info.get("server") or "Not exposed"),
        ("TLS Status", _title_case(tls.get("status", "n/a"))),
        ("TLS Version", tls.get("tls_version") or "n/a"),
        ("Certificate Days Remaining", str(tls.get("days_remaining", "n/a"))),
        (
            "Missing Security Headers",
            ", ".join(security_headers.get("missing", [])) or "None detected",
        ),
    ]

    table_rows = [
        [
            Paragraph(escape(label), styles["table_label"]),
            Paragraph(escape(str(value)), styles["table_value"]),
        ]
        for label, value in rows
    ]
    table = Table(table_rows, colWidths=[48 * mm, 134 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _findings_overview(issues: list[dict], styles: dict) -> Table:
    header = [
        Paragraph("Severity", styles["table_label"]),
        Paragraph("Title", styles["table_label"]),
        Paragraph("Category", styles["table_label"]),
    ]
    rows = [header]
    for issue in issues[:12]:
        rows.append(
            [
                Paragraph(escape(_severity_label(issue.get("severity"))), styles["table_value"]),
                Paragraph(escape(issue.get("title", "Untitled finding")), styles["table_value"]),
                Paragraph(escape(_category_label(issue.get("category"))), styles["table_value"]),
            ]
        )

    if len(rows) == 1:
        rows.append(
            [
                Paragraph("Info", styles["table_value"]),
                Paragraph("No findings detected.", styles["table_value"]),
                Paragraph("Assessment", styles["table_value"]),
            ]
        )

    table = Table(rows, colWidths=[24 * mm, 106 * mm, 52 * mm], hAlign="LEFT")
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]
    for row_index, issue in enumerate(issues[:12], start=1):
        style_commands.append(("BACKGROUND", (0, row_index), (0, row_index), _severity_fill(issue.get("severity"))))
        style_commands.append(("TEXTCOLOR", (0, row_index), (0, row_index), colors.white))

    table.setStyle(TableStyle(style_commands))
    return table


def _finding_card(index: int, issue: dict, styles: dict) -> list:
    severity = issue.get("severity", "low")
    badge = Table([[Paragraph(_severity_label(severity), styles["small"])]], colWidths=[24 * mm])
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(severity, colors.HexColor("#334155"))),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    header = Table(
        [
            [
                badge,
                Paragraph(escape(f"{index}. {issue.get('title', 'Untitled finding')}"), styles["finding_title"]),
            ],
            [
                "",
                Paragraph(
                    escape(
                        f"Category: {_category_label(issue.get('category'))} | Trend: {_title_case(issue.get('history_status', 'new'))}"
                    ),
                    styles["finding_meta"],
                ),
            ],
        ],
        colWidths=[28 * mm, 154 * mm],
        hAlign="LEFT",
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    blocks = [
        _text_block("Description", issue.get("details", "No description provided."), styles),
        _text_block("Evidence", issue.get("evidence", "No evidence captured."), styles),
        _text_block("Remediation", issue.get("recommendation", "No recommendation provided."), styles),
    ]

    card = Table([[header], [blocks[0]], [blocks[1]], [blocks[2]]], colWidths=[182 * mm], hAlign="LEFT")
    card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return [card, Spacer(1, 4 * mm)]


def _text_block(label: str, text: str, styles: dict) -> Table:
    table = Table(
        [
            [Paragraph(label, styles["finding_block_label"])],
            [Paragraph(escape(_normalize_text(text)), styles["finding_block_body"])],
        ],
        colWidths=[176 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _empty_state(styles: dict) -> Table:
    table = Table([[Paragraph("No findings were recorded for this scan run.", styles["empty"])]], colWidths=[182 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _sorted_issues(issues: list[dict]) -> list[dict]:
    return sorted(
        issues,
        key=lambda issue: (
            SEVERITY_ORDER.get(issue.get("severity", "low"), 99),
            issue.get("category", ""),
            issue.get("title", ""),
        ),
    )


def _severity_label(value: str | None) -> str:
    return SEVERITY_LABELS.get((value or "").lower(), (value or "Info").title())


def _category_label(value: str | None) -> str:
    return CATEGORY_LABELS.get(value or "", value or "General")


def _severity_fill(value: str | None):
    return SEVERITY_COLORS.get((value or "").lower(), colors.HexColor("#475569"))


def _title_case(value: str) -> str:
    return value.replace("_", " ").title()


def _normalize_text(value: str) -> str:
    return " ".join(str(value).split())


def _draw_page_chrome(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, A4[1] - 10 * mm, A4[0] - doc.rightMargin, A4[1] - 10 * mm)
    canvas.line(doc.leftMargin, 10 * mm, A4[0] - doc.rightMargin, 10 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(doc.leftMargin, 6 * mm, "WeakScan Assessment Report")
    canvas.drawRightString(A4[0] - doc.rightMargin, 6 * mm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()
