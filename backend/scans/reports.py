from pathlib import Path
from xml.sax.saxutils import escape

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import ScanJob


FONT_NAME = "STSong-Light"


def generate_scan_pdf(scan_job: ScanJob) -> Path:
    _register_fonts()

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

    styles = _build_styles()
    findings = scan_job.findings or {}
    issues = findings.get("issues", [])
    summary = findings.get("summary", {})
    tls = findings.get("tls", {})
    security_headers = findings.get("security_headers", {})
    target = findings.get("target", {})
    http_info = findings.get("http", {})

    story = [
        _hero_block(scan_job, summary, styles),
        Spacer(1, 10),
        _summary_grid(summary, styles),
        Spacer(1, 10),
        _overview_table(scan_job, target, http_info, tls, security_headers, styles),
        Spacer(1, 12),
        Paragraph("風險明細", styles["section_title"]),
        Spacer(1, 6),
    ]

    if not issues:
        story.append(_empty_state(styles))
    else:
        for index, issue in enumerate(issues, start=1):
            story.extend(_issue_card(index, issue, styles))

    doc.build(story)
    return report_path


def _register_fonts() -> None:
    try:
        pdfmetrics.getFont(FONT_NAME)
    except KeyError:
        pdfmetrics.registerFont(UnicodeCIDFont(FONT_NAME))


def _build_styles():
    sample = getSampleStyleSheet()
    return {
        "hero_kicker": ParagraphStyle(
            "HeroKicker",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#d97706"),
            alignment=TA_CENTER,
        ),
        "hero_title": ParagraphStyle(
            "HeroTitle",
            parent=sample["Title"],
            fontName=FONT_NAME,
            fontSize=24,
            leading=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0f172a"),
        ),
        "hero_subtitle": ParagraphStyle(
            "HeroSubtitle",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=11,
            leading=16,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#475569"),
        ),
        "section_title": ParagraphStyle(
            "SectionTitle",
            parent=sample["Heading2"],
            fontName=FONT_NAME,
            fontSize=15,
            leading=20,
            textColor=colors.HexColor("#111827"),
        ),
        "body": ParagraphStyle(
            "Body",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#334155"),
        ),
        "body_strong": ParagraphStyle(
            "BodyStrong",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#0f172a"),
        ),
        "metric_label": ParagraphStyle(
            "MetricLabel",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#64748b"),
        ),
        "metric_value": ParagraphStyle(
            "MetricValue",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0f172a"),
        ),
        "issue_title": ParagraphStyle(
            "IssueTitle",
            parent=sample["Heading3"],
            fontName=FONT_NAME,
            fontSize=12,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
        ),
        "issue_meta": ParagraphStyle(
            "IssueMeta",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#64748b"),
        ),
        "issue_detail": ParagraphStyle(
            "IssueDetail",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#334155"),
        ),
        "empty": ParagraphStyle(
            "Empty",
            parent=sample["BodyText"],
            fontName=FONT_NAME,
            fontSize=10,
            leading=16,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#475569"),
        ),
    }


def _hero_block(scan_job: ScanJob, summary: dict, styles: dict) -> Table:
    status_label = _translate_status(scan_job.status)
    issue_count = summary.get("issue_count", 0)
    hero_content = [
        [Paragraph("WeakScan 弱掃報告", styles["hero_kicker"])],
        [Paragraph(escape(scan_job.project_name), styles["hero_title"])],
        [
            Paragraph(
                f"本報告為網站 / API 基礎弱掃結果摘要，狀態：{escape(status_label)}，共發現 {issue_count} 項風險訊號。",
                styles["hero_subtitle"],
            )
        ],
    ]
    table = Table(hero_content, colWidths=[182 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff7ed")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#fdba74")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ]
        )
    )
    return table


def _summary_grid(summary: dict, styles: dict) -> Table:
    metrics = [
        ("總問題數", summary.get("issue_count", 0)),
        ("嚴重", summary.get("critical_count", 0)),
        ("高風險", summary.get("high_count", 0)),
        ("中風險", summary.get("medium_count", 0)),
    ]

    cells = []
    for label, value in metrics:
        inner = Table(
            [
                [Paragraph(label, styles["metric_label"])],
                [Paragraph(str(value), styles["metric_value"])],
            ],
            colWidths=[43 * mm],
        )
        inner.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        cells.append(inner)

    table = Table([cells], colWidths=[43 * mm] * 4, hAlign="LEFT")
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    return table


def _overview_table(scan_job: ScanJob, target: dict, http_info: dict, tls: dict, security_headers: dict, styles: dict) -> Table:
    rows = [
        ["掃描類型", _translate_scan_type(scan_job.scan_type)],
        ["目標網址", scan_job.target_url],
        ["解析 IP", target.get("resolved_ip") or "無"],
        ["HTTP 狀態", str(http_info.get("status_code", "n/a"))],
        ["TLS 狀態", _translate_tls_status(tls.get("status", "n/a"))],
        ["憑證剩餘天數", str(tls.get("days_remaining", "n/a"))],
        ["缺少安全標頭", "、".join(_translate_header(item) for item in security_headers.get("missing", [])) or "無"],
    ]

    table_data = []
    for label, value in rows:
        table_data.append(
            [
                Paragraph(escape(label), styles["body_strong"]),
                Paragraph(escape(str(value)), styles["body"]),
            ]
        )

    table = Table(table_data, colWidths=[38 * mm, 144 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ]
        )
    )
    return table


def _issue_card(index: int, issue: dict, styles: dict) -> list:
    severity_label = _translate_severity(issue.get("severity", ""))
    category_label = _translate_category(issue.get("category", ""))
    title = _translate_issue_title(issue)
    detail = issue.get("details", "")

    badge_color = _severity_color(issue.get("severity", ""))
    badge = Table([[Paragraph(severity_label, styles["metric_label"])]], colWidths=[28 * mm])
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), badge_color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0, badge_color),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    issue_table = Table(
        [
            [badge, Paragraph(f"{index}. {escape(title)}", styles["issue_title"])],
            ["", Paragraph(f"分類：{escape(category_label)}", styles["issue_meta"])],
            ["", Paragraph(escape(detail), styles["issue_detail"])],
        ],
        colWidths=[32 * mm, 150 * mm],
        hAlign="LEFT",
    )
    issue_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return [issue_table, Spacer(1, 8)]


def _empty_state(styles: dict) -> Table:
    table = Table([[Paragraph("本次基礎檢查未發現明顯風險訊號。", styles["empty"])]], colWidths=[182 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    return table


def _translate_scan_type(value: str) -> str:
    return {"web": "網站掃描", "api": "API 掃描"}.get(value, value)


def _translate_status(value: str) -> str:
    return {
        "pending": "等待中",
        "running": "掃描中",
        "completed": "已完成",
        "failed": "失敗",
    }.get(value, value)


def _translate_tls_status(value: str) -> str:
    return {
        "ok": "正常",
        "not_applicable": "不適用",
        "error": "異常",
    }.get(value, value)


def _translate_severity(value: str) -> str:
    return {
        "critical": "嚴重",
        "high": "高風險",
        "medium": "中風險",
        "low": "低風險",
    }.get(value, value or "未分類")


def _translate_category(value: str) -> str:
    return {
        "security_headers": "安全標頭",
        "tls": "TLS / 憑證",
        "sensitive_path": "敏感路徑",
        "api_surface": "API 暴露面",
        "cors": "跨來源設定",
    }.get(value, value)


def _translate_header(value: str) -> str:
    return {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "Referrer-Policy": "Referrer-Policy",
    }.get(value, value)


def _translate_issue_title(issue: dict) -> str:
    title = issue.get("title", "")
    path = issue.get("details", "")

    if title.startswith("Missing "):
        return f"缺少安全標頭：{title.replace('Missing ', '')}"
    if title == "TLS certificate expires soon":
        return "TLS 憑證即將到期"
    if title == "TLS inspection failed":
        return "TLS 檢查失敗"
    if title.startswith("Sensitive path exposed:"):
        return f"敏感路徑外露：{title.split(':', 1)[-1].strip()}"
    if title.startswith("Public API documentation exposed:"):
        return f"公開 API 文件外露：{title.split(':', 1)[-1].strip()}"
    if title == "Wildcard CORS policy detected":
        return "偵測到萬用字元 CORS 設定"
    return title or path or "未命名風險"


def _severity_color(value: str):
    return {
        "critical": colors.HexColor("#be123c"),
        "high": colors.HexColor("#dc2626"),
        "medium": colors.HexColor("#d97706"),
        "low": colors.HexColor("#475569"),
    }.get(value, colors.HexColor("#334155"))
