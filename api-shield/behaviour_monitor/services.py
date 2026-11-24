import hashlib
from datetime import timedelta

from django.conf import settings
from django.db.models import Count, Q
from django.utils import timezone

from .models import ApiRequestLog, BehaviourAlert

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def _setting(name, default):
    return settings.APISHIELD.get(name, default)


def _window_minutes():
    return max(1, int(_setting("BEHAVIOUR_WINDOW_MINUTES", 10)))


def _window_start(now=None):
    return (now or timezone.now()) - timedelta(minutes=_window_minutes())


def _fingerprint(*parts):
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def record_request(
    *,
    organization,
    project,
    endpoint=None,
    method,
    path,
    ip_address=None,
    user_agent="",
    status_code=None,
    response_time_ms=0,
    query_keys=None,
):
    return ApiRequestLog.objects.create(
        organization=organization,
        project=project,
        endpoint=endpoint,
        method=(method or "GET")[:10],
        path=path[:500],
        ip_address=ip_address,
        user_agent=(user_agent or "")[:500],
        status_code=status_code,
        response_time_ms=max(0, min(int(response_time_ms or 0), 2147483647)),
        query_keys=[str(key) for key in (query_keys or [])],
    )


def _create_alert(
    *,
    organization,
    project,
    alert_type,
    severity,
    title,
    description,
    evidence,
    dedupe_parts,
    endpoint_id=None,
):
    fingerprint = _fingerprint(alert_type, *dedupe_parts)
    evidence = dict(evidence)
    evidence["fingerprint"] = fingerprint
    recent_open = BehaviourAlert.objects.filter(
        organization=organization,
        project=project,
        alert_type=alert_type,
        status=BehaviourAlert.Status.OPEN,
        created_at__gte=_window_start(),
        evidence__fingerprint=fingerprint,
    ).exists()
    if recent_open:
        return None
    return BehaviourAlert.objects.create(
        organization=organization,
        project=project,
        endpoint_id=endpoint_id,
        alert_type=alert_type,
        severity=severity,
        title=title[:220],
        description=description,
        evidence=evidence,
    )


def _severity_for_ratio(ratio):
    if ratio >= 3:
        return BehaviourAlert.Severity.CRITICAL
    if ratio >= 2:
        return BehaviourAlert.Severity.HIGH
    return BehaviourAlert.Severity.MEDIUM


def _detect_high_frequency(group_logs, project, organization, ip, scope):
    threshold = max(1, int(_setting("REQUEST_FREQUENCY_THRESHOLD", 120)))
    total = group_logs.count()
    if total < threshold:
        return None
    alert = _create_alert(
        organization=organization,
        project=project,
        endpoint_id=group_logs.values_list("endpoint_id", flat=True).first(),
        alert_type=BehaviourAlert.AlertType.HIGH_FREQUENCY,
        severity=_severity_for_ratio(total / threshold),
        title=f"High request frequency from {ip or 'unknown source'}",
        description=(
            f"{total} requests were recorded within {_window_minutes()} minutes, exceeding the "
            f"configured threshold of {threshold}."
        ),
        evidence={
            "scope": scope,
            "ip_address": ip,
            "request_count": total,
            "threshold": threshold,
            "window_minutes": _window_minutes(),
        },
        dedupe_parts=(scope, project.id, ip or "unknown"),
    )
    if alert is not None:
        group_logs.update(is_suspicious=True)
    return alert


def _detect_repeated_failures(group_logs, project, organization, ip, scope):
    threshold = max(1, int(_setting("FAILED_REQUEST_THRESHOLD", 12)))
    failed_logs = group_logs.filter(status_code__gte=400)
    failed_count = failed_logs.count()
    if failed_count < threshold:
        return None
    alert = _create_alert(
        organization=organization,
        project=project,
        endpoint_id=failed_logs.values_list("endpoint_id", flat=True).first(),
        alert_type=BehaviourAlert.AlertType.REPEATED_FAILURES,
        severity=_severity_for_ratio(failed_count / threshold),
        title=f"Repeated failed requests from {ip or 'unknown source'}",
        description=(
            f"{failed_count} failed API responses were recorded within {_window_minutes()} minutes, "
            f"exceeding the configured threshold of {threshold}."
        ),
        evidence={
            "scope": scope,
            "ip_address": ip,
            "failed_count": failed_count,
            "threshold": threshold,
            "window_minutes": _window_minutes(),
        },
        dedupe_parts=(scope, project.id, ip or "unknown"),
    )
    if alert is not None:
        failed_logs.update(is_suspicious=True)
    return alert


def _detect_sensitive_access(group_logs, project, organization, ip, scope):
    terms = [str(term).lower() for term in _setting("SENSITIVE_PATH_TERMS", []) if str(term).strip()]
    if not terms:
        return []
    path_query = Q()
    for term in terms:
        path_query |= Q(path__icontains=term)
    matched = group_logs.filter(path_query)
    created = []
    for path, endpoint_id, count in matched.values("path", "endpoint_id").annotate(count=Count("id")):
        matched_terms = [term for term in terms if term in (path or "").lower()]
        threshold = max(1, int(_setting("FAILED_REQUEST_THRESHOLD", 12)))
        alert = _create_alert(
            organization=organization,
            project=project,
            endpoint_id=endpoint_id,
            alert_type=BehaviourAlert.AlertType.SENSITIVE_ENDPOINT,
            severity=BehaviourAlert.Severity.HIGH if count >= threshold else BehaviourAlert.Severity.MEDIUM,
            title=f"Sensitive endpoint accessed: {path}",
            description=(
                f"{count} request(s) to a path matching configured sensitive terms "
                f"({', '.join(matched_terms)}) were recorded from {ip or 'unknown source'}."
            ),
            evidence={
                "scope": scope,
                "ip_address": ip,
                "path": path,
                "matched_terms": matched_terms,
                "request_count": count,
                "window_minutes": _window_minutes(),
            },
            dedupe_parts=(scope, project.id, ip or "unknown", path),
        )
        if alert is not None:
            matched.filter(path=path, endpoint_id=endpoint_id).update(is_suspicious=True)
            created.append(alert)
    return created


def _detect_unusual_pattern(group_logs, project, organization, ip, scope):
    failure_threshold = max(1, int(_setting("FAILED_REQUEST_THRESHOLD", 12)))
    frequency_threshold = max(1, int(_setting("REQUEST_FREQUENCY_THRESHOLD", 120)))
    volume = max(failure_threshold, frequency_threshold // 2)
    total = group_logs.count()
    if total < volume:
        return None
    distinct_paths = group_logs.values("path").distinct().count()
    distinct_methods = group_logs.values("method").distinct().count()
    mutating_count = group_logs.filter(method__in=MUTATING_METHODS).count()
    enumeration = distinct_paths >= max(3, frequency_threshold // 20) and distinct_methods >= 2
    write_heavy = mutating_count >= total * 0.75 and distinct_paths >= 2
    if not enumeration and not write_heavy:
        return None
    alert = _create_alert(
        organization=organization,
        project=project,
        endpoint=group_logs.values_list("endpoint_id", flat=True).first(),
        alert_type=BehaviourAlert.AlertType.UNUSUAL_PATTERN,
        severity=BehaviourAlert.Severity.HIGH,
        title=f"Unusual request pattern from {ip or 'unknown source'}",
        description=(
            f"{total} requests touched {distinct_paths} paths using {distinct_methods} methods; "
            f"{mutating_count} were state-changing requests."
        ),
        evidence={
            "scope": scope,
            "ip_address": ip,
            "request_count": total,
            "distinct_paths": distinct_paths,
            "distinct_methods": distinct_methods,
            "mutating_requests": mutating_count,
            "minimum_volume": volume,
            "window_minutes": _window_minutes(),
        },
        dedupe_parts=(scope, project.id, ip or "unknown"),
    )
    if alert is not None:
        group_logs.update(is_suspicious=True)
    return alert


def _analyse_subset(logs, organization, now, scope):
    from api_projects.models import ApiProject

    created = []
    grouped = list(logs.values("project_id", "ip_address").distinct())
    project_ids = {row["project_id"] for row in grouped}
    projects = {
        project.id: project for project in ApiProject.objects.filter(organization=organization, id__in=project_ids)
    }
    for row in grouped:
        project = projects.get(row["project_id"])
        if project is None:
            continue
        ip = row["ip_address"]
        group_logs = logs.filter(project_id=project.id)
        if ip is None:
            group_logs = group_logs.filter(ip_address__isnull=True)
        else:
            group_logs = group_logs.filter(ip_address=ip)
        for detector in (_detect_high_frequency, _detect_repeated_failures, _detect_unusual_pattern):
            alert = detector(group_logs, project, organization, ip, scope)
            if alert is not None:
                created.append(alert)
        created.extend(_detect_sensitive_access(group_logs, project, organization, ip, scope))
    return created


def analyse_organization(organization, project=None, now=None):
    now = now or timezone.now()
    logs = ApiRequestLog.objects.filter(organization=organization, timestamp__gte=_window_start(now))
    if project is not None:
        logs = logs.filter(project=project)
    return _analyse_subset(logs, organization, now, "organization")


def analyse_request_log(log):
    now = log.timestamp or timezone.now()
    logs = ApiRequestLog.objects.filter(
        organization=log.organization,
        timestamp__gte=_window_start(now),
        project=log.project,
    )
    if log.ip_address:
        logs = logs.filter(ip_address=log.ip_address)
        scope = f"ip:{log.ip_address}"
    else:
        logs = logs.filter(ip_address__isnull=True)
        scope = "ip:unknown"
    return _analyse_subset(logs, log.organization, now, scope)


def update_alert_status(alert, status, actor=None):
    history = list(alert.evidence.get("status_history", []))
    history.append(
        {
            "from": alert.status,
            "to": status,
            "actor": getattr(actor, "email", None),
            "at": timezone.now().isoformat(),
        }
    )
    alert.evidence["status_history"] = history
    alert.status = status
    alert.save(update_fields=["status", "evidence", "updated_at"])
    return alert
