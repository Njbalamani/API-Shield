import html
import json
import logging
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db.models import Avg, Count, Max, Q
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from api_scanner.models import ScanFinding, ScanRun
from authentication_audit.models import AuthenticationAudit
from behaviour_monitor.models import ApiRequestLog, BehaviourAlert
from endpoint_discovery.models import ApiEndpoint
from vulnerability_manager.models import VulnerabilityAssignment

from .models import Report

logger = logging.getLogger("apishield")


def _scan_for_report(report):
    if report.scan_run_id:
        return report.scan_run
    return (
        ScanRun.objects.filter(
            organization=report.organization,
            project=report.project,
            status=ScanRun.Status.COMPLETED,
        )
        .order_by("-started_at")
        .first()
    )


def _finding_payload(finding, assignments):
    assignment = assignments.get(finding.id)
    remediation = finding.remediation
    if isinstance(remediation, dict):
        remediation_text = (
            remediation.get("summary") or remediation.get("description") or remediation.get("recommendation") or ""
        )
    else:
        remediation_text = str(remediation or "")
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "owasp_category": finding.owasp_category or "Unmapped",
        "cwe": finding.cwe,
        "status": finding.status,
        "risk_score": finding.risk_score,
        "endpoint": str(finding.endpoint) if finding.endpoint_id else None,
        "scan_id": finding.scan_run_id,
        "assignee": assignment.assignee.email if assignment and assignment.assignee_id else None,
        "assignment_status": assignment.get_status_display() if assignment else None,
        "priority": assignment.get_priority_display() if assignment else None,
        "remediation": remediation_text,
        "evidence": finding.evidence if isinstance(finding.evidence, dict) else {},
    }


def build_report_data(report):
    organization = report.organization
    project = report.project
    parameters = report.parameters or {}
    scan = _scan_for_report(report)
    findings = ScanFinding.objects.filter(
        scan_run__organization=organization,
        scan_run__project=project,
    ).select_related("scan_run", "endpoint")
    if scan is not None:
        findings = findings.filter(scan_run=scan)
    if report.report_type == Report.ReportType.ENDPOINT and parameters.get("endpoint_id"):
        findings = findings.filter(endpoint_id=parameters["endpoint_id"])
    finding_list = list(findings.order_by("-risk_score", "-created_at"))
    assignments = {
        assignment.finding_id: assignment
        for assignment in VulnerabilityAssignment.objects.filter(finding__in=finding_list).select_related("assignee")
    }
    findings_data = [_finding_payload(finding, assignments) for finding in finding_list]

    severity_distribution = list(findings.values("severity").annotate(count=Count("id")).order_by("severity"))
    status_distribution = list(findings.values("status").annotate(count=Count("id")).order_by("status"))
    owasp_distribution = list(
        findings.exclude(owasp_category="")
        .values("owasp_category")
        .annotate(count=Count("id"))
        .order_by("-count", "owasp_category")
    )
    risk_aggregate = findings.aggregate(average_risk=Avg("risk_score"), maximum_risk=Max("risk_score"))
    scan_risk = float(scan.risk_score) if scan is not None else 0.0
    average_risk = float(risk_aggregate["average_risk"] or 0)
    maximum_risk = float(risk_aggregate["maximum_risk"] or 0)
    risk_score = round(max(scan_risk, average_risk, maximum_risk), 2)

    endpoints = ApiEndpoint.objects.filter(project=project)
    if report.report_type == Report.ReportType.ENDPOINT and parameters.get("endpoint_id"):
        endpoints = endpoints.filter(id=parameters["endpoint_id"])
    endpoints_data = list(
        endpoints.values("id", "method", "path", "summary", "risk_level", "auth_required", "is_active")
    )

    auth_audits = AuthenticationAudit.objects.filter(organization=organization, project=project)
    if scan is not None:
        auth_audits = auth_audits.filter(Q(scan_run=scan) | Q(scan_run__isnull=True))
    auth_data = list(
        auth_audits.values(
            "auth_type",
            "result",
            "score",
            "expiration_detected",
            "insecure_token_handling",
            "authorization_controls",
            "endpoint__path",
            "findings",
            "created_at",
        )
    )
    auth_aggregate = auth_audits.aggregate(average_score=Avg("score"), failed=Count("id", filter=Q(result="fail")))

    alerts = BehaviourAlert.objects.filter(organization=organization, project=project)
    logs = ApiRequestLog.objects.filter(organization=organization, project=project)
    behaviour_data = {
        "total_requests": logs.count(),
        "suspicious_requests": logs.filter(is_suspicious=True).count(),
        "failed_requests": logs.filter(status_code__gte=400).count(),
        "alerts": list(alerts.values("title", "alert_type", "severity", "status", "created_at", "description")),
        "open_alerts": alerts.filter(status=BehaviourAlert.Status.OPEN).count(),
    }

    metadata = {
        "organization": {
            "id": organization.id,
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
        },
        "project": {
            "id": project.id,
            "name": project.name,
            "slug": project.slug,
            "environment": project.environment,
            "base_url": project.base_url,
            "status": project.status,
            "authorization_reference": project.authorization_reference,
        },
        "scan": None
        if scan is None
        else {
            "id": scan.id,
            "status": scan.status,
            "mode": scan.mode,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "risk_score": scan.risk_score,
            "findings_count": scan.findings_count,
            "critical_count": scan.critical_count,
        },
        "report": {
            "id": report.id,
            "report_type": report.report_type,
            "file_format": report.file_format,
            "parameters": parameters,
            "created_by": report.created_by.email if report.created_by_id else None,
        },
        "generated_at": timezone.now().isoformat(),
    }
    summary = {
        "total_endpoints": endpoints.count(),
        "total_scans": ScanRun.objects.filter(organization=organization, project=project).count(),
        "total_findings": len(findings_data),
        "critical_findings": sum(1 for item in findings_data if item["severity"] == "critical"),
        "high_findings": sum(1 for item in findings_data if item["severity"] == "high"),
        "open_findings": sum(1 for item in findings_data if item["status"] == "open"),
        "api_risk_score": risk_score,
        "average_finding_risk": round(average_risk, 2),
        "maximum_finding_risk": round(maximum_risk, 2),
        "authentication_score": round(float(auth_aggregate["average_score"] or 0), 2),
        "failed_authentication_checks": auth_aggregate["failed"],
        "behaviour_alerts": behaviour_data["open_alerts"],
    }
    return {
        "metadata": metadata,
        "summary": summary,
        "severity_distribution": severity_distribution,
        "status_distribution": status_distribution,
        "owasp_distribution": owasp_distribution,
        "findings": findings_data,
        "endpoints": endpoints_data,
        "authentication": auth_data,
        "behaviour": behaviour_data,
    }


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ApishieldTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "ApishieldSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14,
        ),
        "heading": ParagraphStyle(
            "ApishieldHeading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "ApishieldBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=4,
        ),
        "table_header": ParagraphStyle(
            "ApishieldTableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "table_cell": ParagraphStyle(
            "ApishieldTableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b"),
        ),
    }


def _escaped(value):
    return html.escape("" if value is None else str(value))


def _table(headers, rows, styles, widths=None):
    data = [[Paragraph(_escaped(header), styles["table_header"]) for header in headers]]
    if not rows:
        data.append([Paragraph("No data available", styles["table_cell"])] + [""] * (len(headers) - 1))
    for row in rows:
        data.append([Paragraph(_escaped(cell), styles["table_cell"]) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 10 * mm, "APIShield - Confidential Security Report")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf(data):
    from io import BytesIO

    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"APIShield {data['metadata']['report']['report_type']} report",
        author="APIShield",
    )
    metadata = data["metadata"]
    summary = data["summary"]
    story = [
        Paragraph("APIShield Security Assessment", styles["title"]),
        Paragraph(
            f"{metadata['organization']['name']} / {metadata['project']['name']} - "
            f"{metadata['report']['report_type'].replace('_', ' ').title()} Report",
            styles["subtitle"],
        ),
    ]
    story.append(
        _table(
            ["Field", "Value"],
            [
                ["Organization", metadata["organization"]["name"]],
                ["Organization slug", metadata["organization"]["slug"]],
                ["Project", metadata["project"]["name"]],
                ["Environment", metadata["project"]["environment"]],
                ["Base URL", metadata["project"]["base_url"] or "Not configured"],
                ["Authorization reference", metadata["project"]["authorization_reference"] or "Not provided"],
                ["Report type", metadata["report"]["report_type"]],
                ["Generated at", metadata["generated_at"]],
                ["Generated by", metadata["report"]["created_by"] or "System"],
                ["Scan", metadata["scan"]["id"] if metadata["scan"] else "No scan selected"],
            ],
            styles,
            widths=[45 * mm, 129 * mm],
        )
    )
    story.append(Paragraph("Executive Summary", styles["heading"]))
    story.append(
        _table(
            ["Metric", "Value"],
            [[key.replace("_", " ").title(), value] for key, value in summary.items()],
            styles,
            widths=[100 * mm, 74 * mm],
        )
    )
    story.append(Paragraph("Severity Distribution", styles["heading"]))
    story.append(
        _table(
            ["Severity", "Count"],
            [[item["severity"], item["count"]] for item in data["severity_distribution"]],
            styles,
            widths=[120 * mm, 54 * mm],
        )
    )
    story.append(Paragraph("OWASP Category Distribution", styles["heading"]))
    story.append(
        _table(
            ["OWASP Category", "Findings"],
            [[item["owasp_category"], item["count"]] for item in data["owasp_distribution"]],
            styles,
            widths=[120 * mm, 54 * mm],
        )
    )
    story.append(PageBreak())
    story.append(Paragraph("Findings", styles["heading"]))
    story.append(
        _table(
            ["ID", "Title", "Severity", "OWASP", "Status", "Risk"],
            [
                [
                    item["id"],
                    item["title"],
                    item["severity"],
                    item["owasp_category"],
                    item["status"],
                    item["risk_score"],
                ]
                for item in data["findings"]
            ],
            styles,
            widths=[12 * mm, 60 * mm, 20 * mm, 42 * mm, 24 * mm, 16 * mm],
        )
    )
    for finding in data["findings"]:
        story.append(Paragraph(f"{finding['id']}. {_escaped(finding['title'])}", styles["heading"]))
        story.append(
            Paragraph(
                f"Severity: {_escaped(finding['severity'])} | Risk score: {finding['risk_score']} | "
                f"OWASP: {_escaped(finding['owasp_category'])} | CWE: {_escaped(finding['cwe'] or '-')}",
                styles["body"],
            )
        )
        story.append(Paragraph(_escaped(finding["description"]), styles["body"]))
        if finding["endpoint"]:
            story.append(Paragraph(f"Endpoint: {_escaped(finding['endpoint'])}", styles["body"]))
        if finding["remediation"]:
            story.append(Paragraph(f"Remediation: {_escaped(finding['remediation'])}", styles["body"]))
        if finding["assignee"]:
            story.append(
                Paragraph(
                    f"Owner: {_escaped(finding['assignee'])} | Priority: {_escaped(finding['priority'])} | "
                    f"Status: {_escaped(finding['assignment_status'])}",
                    styles["body"],
                )
            )
        story.append(Spacer(1, 4 * mm))
    report_type = metadata["report"]["report_type"]
    if report_type in {Report.ReportType.FULL, Report.ReportType.ENDPOINT}:
        story.append(PageBreak())
        story.append(Paragraph("API Endpoints", styles["heading"]))
        story.append(
            _table(
                ["ID", "Method", "Path", "Risk", "Auth", "Active"],
                [
                    [
                        item["id"],
                        item["method"],
                        item["path"],
                        item["risk_level"],
                        "Yes" if item["auth_required"] else "No",
                        "Yes" if item["is_active"] else "No",
                    ]
                    for item in data["endpoints"]
                ],
                styles,
                widths=[12 * mm, 18 * mm, 88 * mm, 20 * mm, 16 * mm, 20 * mm],
            )
        )
    if report_type in {Report.ReportType.FULL, Report.ReportType.AUTH}:
        story.append(Paragraph("Authentication Audits", styles["heading"]))
        story.append(
            _table(
                ["Auth type", "Result", "Score", "Endpoint", "Created"],
                [
                    [
                        item["auth_type"],
                        item["result"],
                        item["score"],
                        item["endpoint__path"] or "Project",
                        item["created_at"],
                    ]
                    for item in data["authentication"]
                ],
                styles,
                widths=[24 * mm, 18 * mm, 16 * mm, 90 * mm, 26 * mm],
            )
        )
    if report_type in {Report.ReportType.FULL, Report.ReportType.BEHAVIOUR}:
        story.append(Paragraph("Behaviour Monitoring", styles["heading"]))
        behaviour = data["behaviour"]
        story.append(
            Paragraph(
                f"Requests: {behaviour['total_requests']} | Suspicious: {behaviour['suspicious_requests']} | "
                f"Failed: {behaviour['failed_requests']} | Open alerts: {behaviour['open_alerts']}",
                styles["body"],
            )
        )
        story.append(
            _table(
                ["Alert", "Type", "Severity", "Status", "Created"],
                [
                    [item["title"], item["alert_type"], item["severity"], item["status"], item["created_at"]]
                    for item in behaviour["alerts"]
                ],
                styles,
                widths=[64 * mm, 36 * mm, 22 * mm, 26 * mm, 26 * mm],
            )
        )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def render_json(data):
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def generate_report(report):
    try:
        data = build_report_data(report)
        if report.file_format == Report.FileFormat.JSON:
            content = render_json(data)
            extension = "json"
        else:
            content = render_pdf(data)
            extension = "pdf"
        Path(settings.REPORTS_ROOT).mkdir(parents=True, exist_ok=True)
        report.file.save(f"reports/{uuid4().hex}.{extension}", ContentFile(content), save=False)
        report.status = Report.Status.COMPLETED
        report.error_message = ""
        report.save(update_fields=["file", "status", "error_message"])
    except Exception as exc:
        logger.exception("report generation failed", extra={"report_id": report.pk})
        report.status = Report.Status.FAILED
        report.error_message = f"{type(exc).__name__}: {exc}"[:1000]
        report.save(update_fields=["status", "error_message"])
    return report


def create_report(organization, project, *, created_by, report_type, file_format, scan_run=None, parameters=None):
    if project.organization_id != organization.id:
        raise ValidationError("Project does not belong to the current organization.")
    if scan_run is not None and (scan_run.organization_id != organization.id or scan_run.project_id != project.id):
        raise ValidationError("Scan run does not belong to the selected project.")
    report = Report.objects.create(
        organization=organization,
        project=project,
        scan_run=scan_run,
        created_by=created_by,
        report_type=report_type,
        file_format=file_format,
        parameters=parameters or {},
        status=Report.Status.PENDING,
    )
    return generate_report(report)


def report_download(report):
    if not report.file:
        raise FileNotFoundError("Report file is not available.")
    filename = Path(report.file.name).name
    if not filename or filename in {".", ".."} or Path(filename).name != filename:
        raise ValueError("Invalid report file name.")
    content_type = "application/json" if report.file_format == Report.FileFormat.JSON else "application/pdf"
    return report.file.storage.open(report.file.name, "rb"), filename, content_type
