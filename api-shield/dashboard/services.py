from datetime import timedelta

from django.db.models import Avg, Count, Max, OuterRef, Q, Subquery
from django.db.models.functions import TruncDate
from django.utils import timezone

from api_projects.models import ApiProject
from api_scanner.models import ScanFinding, ScanRun
from authentication_audit.models import AuthenticationAudit
from behaviour_monitor.models import BehaviourAlert
from endpoint_discovery.models import ApiEndpoint


def _bounded_days(days):
    try:
        value = int(days)
    except (TypeError, ValueError):
        value = 7
    return max(1, min(value, 365))


def get_metrics(organization, days=7):
    if organization is None:
        return {}
    days = _bounded_days(days)
    now = timezone.now()
    start = now - timedelta(days=days)
    endpoints = ApiEndpoint.objects.filter(project__organization=organization)
    projects = ApiProject.objects.filter(organization=organization)
    scans = ScanRun.objects.filter(organization=organization)
    findings = ScanFinding.objects.filter(scan_run__organization=organization)
    alerts = BehaviourAlert.objects.filter(organization=organization)
    auth_audits = AuthenticationAudit.objects.filter(organization=organization)

    latest_scan_risk = (
        scans.filter(status=ScanRun.Status.COMPLETED, project_id=OuterRef("pk"))
        .order_by("-started_at")
        .values("risk_score")[:1]
    )
    project_risk = projects.annotate(latest_risk=Subquery(latest_scan_risk)).aggregate(
        average_latest_risk=Avg("latest_risk"),
        maximum_latest_risk=Max("latest_risk"),
    )
    finding_risk = findings.aggregate(average_risk=Avg("risk_score"), maximum_risk=Max("risk_score"))
    risk_candidates = [
        value
        for value in (
            project_risk["average_latest_risk"],
            project_risk["maximum_latest_risk"],
            finding_risk["average_risk"],
            finding_risk["maximum_risk"],
        )
        if value is not None
    ]
    api_risk_score = round(max(risk_candidates), 2) if risk_candidates else 0.0

    severity_distribution = list(findings.values("severity").annotate(count=Count("id")).order_by("severity"))
    owasp_distribution = list(
        findings.exclude(owasp_category="")
        .values("owasp_category")
        .annotate(count=Count("id"))
        .order_by("-count", "owasp_category")
    )
    recent_scans = list(
        scans.select_related("project")
        .order_by("-started_at")[:5]
        .values(
            "id",
            "project__name",
            "status",
            "mode",
            "risk_score",
            "findings_count",
            "critical_count",
            "started_at",
            "finished_at",
        )
    )
    scan_trend_rows = (
        scans.filter(started_at__gte=start)
        .annotate(date=TruncDate("started_at"))
        .values("date")
        .annotate(scans=Count("id"))
        .order_by("date")
    )
    finding_trend_rows = (
        findings.filter(created_at__gte=start)
        .annotate(date=TruncDate("created_at"))
        .values("date")
        .annotate(findings=Count("id"))
        .order_by("date")
    )
    trend_map = {}
    for row in scan_trend_rows:
        key = str(row["date"])
        trend_map.setdefault(key, {"date": key, "scans": 0, "findings": 0})["scans"] = row["scans"]
    for row in finding_trend_rows:
        key = str(row["date"])
        trend_map.setdefault(key, {"date": key, "scans": 0, "findings": 0})["findings"] = row["findings"]
    trend = [trend_map[key] for key in sorted(trend_map)]

    auth_aggregate = auth_audits.aggregate(
        average_score=Avg("score"),
        failed_checks=Count("id", filter=Q(result="fail")),
        warning_checks=Count("id", filter=Q(result="warn")),
    )
    alert_counts = alerts.aggregate(
        total=Count("id"),
        open=Count("id", filter=Q(status=BehaviourAlert.Status.OPEN)),
        acknowledged=Count("id", filter=Q(status=BehaviourAlert.Status.ACKNOWLEDGED)),
        resolved=Count("id", filter=Q(status=BehaviourAlert.Status.RESOLVED)),
    )
    return {
        "total_endpoints": endpoints.count(),
        "active_endpoints": endpoints.filter(is_active=True).count(),
        "total_projects": projects.count(),
        "total_scans": scans.count(),
        "completed_scans": scans.filter(status=ScanRun.Status.COMPLETED).count(),
        "running_scans": scans.filter(status=ScanRun.Status.RUNNING).count(),
        "failed_scans": scans.filter(status=ScanRun.Status.FAILED).count(),
        "total_vulnerabilities": findings.count(),
        "open_vulnerabilities": findings.filter(status=ScanFinding.Status.OPEN).count(),
        "critical_findings": findings.filter(severity=ScanFinding.Severity.CRITICAL).count(),
        "high_findings": findings.filter(severity=ScanFinding.Severity.HIGH).count(),
        "verified_findings": findings.filter(verified=True).count(),
        "api_risk_score": api_risk_score,
        "severity_distribution": severity_distribution,
        "owasp_category_distribution": owasp_distribution,
        "recent_scans": recent_scans,
        "trend": trend,
        "trend_days": days,
        "alert_count": alert_counts["total"],
        "open_alert_count": alert_counts["open"],
        "acknowledged_alert_count": alert_counts["acknowledged"],
        "resolved_alert_count": alert_counts["resolved"],
        "authentication_score": round(float(auth_aggregate["average_score"] or 0), 2),
        "failed_authentication_checks": auth_aggregate["failed_checks"],
        "warning_authentication_checks": auth_aggregate["warning_checks"],
    }


def get_topology(organization, include_inactive=False, project=None):
    if organization is None:
        return {"nodes": [], "links": []}
    projects = ApiProject.objects.filter(organization=organization)
    endpoints = ApiEndpoint.objects.filter(project__organization=organization).select_related("project")
    if project is not None:
        projects = projects.filter(id=project.id)
        endpoints = endpoints.filter(project=project)
    if not include_inactive:
        projects = projects.filter(status=ApiProject.Status.ACTIVE)
        endpoints = endpoints.filter(is_active=True, project__status=ApiProject.Status.ACTIVE)
    nodes = []
    links = []
    for item in projects.values("id", "name", "slug", "environment", "status"):
        nodes.append(
            {
                "id": f"project-{item['id']}",
                "label": item["name"],
                "type": "project",
                "metadata": {
                    "project_id": item["id"],
                    "slug": item["slug"],
                    "environment": item["environment"],
                    "status": item["status"],
                },
            }
        )
    for endpoint in endpoints:
        node_id = f"endpoint-{endpoint.id}"
        nodes.append(
            {
                "id": node_id,
                "label": f"{endpoint.method} {endpoint.path}",
                "type": "endpoint",
                "metadata": {
                    "endpoint_id": endpoint.id,
                    "project_id": endpoint.project_id,
                    "method": endpoint.method,
                    "path": endpoint.path,
                    "risk_level": endpoint.risk_level,
                    "auth_required": endpoint.auth_required,
                },
            }
        )
        links.append(
            {
                "source": f"project-{endpoint.project_id}",
                "target": node_id,
                "type": "exposes",
                "method": endpoint.method,
            }
        )
    return {"nodes": nodes, "links": links}
