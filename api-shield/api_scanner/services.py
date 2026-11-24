import logging
from functools import partial
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from accounts.permissions import has_minimum_role

from .engines.base import sanitize_mapping
from .engines.custom import CustomActiveEngine, PassiveSpecEngine, parse_hosts
from .engines.zap import ZapEngine
from .models import ScanFinding, ScanLog, ScanRule, ScanRun

logger = logging.getLogger("apishield")

ACTIVE_MODES = {ScanRun.Mode.ACTIVE, ScanRun.Mode.ZAP, ScanRun.Mode.FULL}
VALID_MODES = {choice[0] for choice in ScanRun.Mode.choices}


def write_log(scan_run, level, message, context=None):
    sanitized_context = sanitize_mapping(context or {})
    ScanLog.objects.create(scan_run=scan_run, level=str(level).upper(), message=message, context=sanitized_context)
    log_method = getattr(logger, str(level).lower(), logger.info)
    log_method("scan_id=%s %s", scan_run.id, message)


def assess_active_authorization(project):
    policy = getattr(project, "scan_policy", None)
    reasons = []
    if not project.authorization_confirmed:
        reasons.append("project authorization has not been confirmed")
    if policy is None:
        reasons.append("no scan policy is configured for the project")
    elif not policy.allow_active_tests:
        reasons.append("scan policy does not allow active tests")
    if not settings.APISHIELD.get("ACTIVE_TESTING_ENABLED"):
        reasons.append("active testing is disabled in APISHIELD settings")
    hostname = (urlparse(str(project.base_url or "")).hostname or "").lower()
    allowed_hosts = parse_hosts(policy.allowed_hosts) if policy else set()
    if not hostname:
        reasons.append("project base URL is missing or invalid")
    elif hostname not in allowed_hosts:
        reasons.append(f"host '{hostname}' is not listed in scan policy allowed hosts")
    return {
        "allowed": not reasons,
        "reasons": reasons,
        "hostname": hostname,
        "allowed_hosts": sorted(allowed_hosts),
    }


def create_scan(project, user, mode, specification=None):
    if not user or not user.is_authenticated:
        raise PermissionDenied("Authentication is required to start a scan.")
    if not has_minimum_role(user, project.organization, "analyst"):
        raise PermissionDenied("You do not have permission to start scans for this organization.")
    if project.status != project.Status.ACTIVE:
        raise ValidationError("Scans can only be started for active projects.")
    if mode not in VALID_MODES:
        raise ValidationError("Unsupported scan mode.")
    if specification is not None and specification.project_id != project.id:
        raise ValidationError("The selected specification does not belong to this project.")

    policy = getattr(project, "scan_policy", None)
    if policy is not None and not policy.allow_passive_tests:
        raise ValidationError("The project scan policy does not allow passive analysis.")

    authorization = assess_active_authorization(project)
    requested_mode = mode
    notes = []
    extra_reasons = []
    if mode in ACTIVE_MODES:
        if mode == ScanRun.Mode.ZAP:
            if not settings.APISHIELD.get("ALLOW_ZAP"):
                extra_reasons.append("ZAP integration is disabled in APISHIELD settings")
            if policy is not None and not policy.allow_zap:
                extra_reasons.append("scan policy does not allow ZAP testing")
        reasons = authorization["reasons"] + extra_reasons
        if reasons:
            mode = ScanRun.Mode.PASSIVE
            note = (
                f"Requested {requested_mode} testing was downgraded to passive analysis because: "
                + "; ".join(reasons)
                + ". No active requests will be sent."
            )
            notes.append(note)

    active_authorized = authorization["allowed"] and mode in ACTIVE_MODES and not extra_reasons
    summary = {
        "notes": notes,
        "mode_requested": requested_mode,
        "mode_effective": mode,
        "active_testing_performed": active_authorized,
        "authorization": {
            "authorization_confirmed": bool(project.authorization_confirmed),
            "active_tests_allowed": bool(authorization["allowed"]),
            "hostname": authorization["hostname"],
            "allowed_hosts": authorization["allowed_hosts"],
            "reasons": authorization["reasons"],
        },
    }
    with transaction.atomic():
        scan_run = ScanRun.objects.create(
            organization=project.organization,
            project=project,
            specification=specification,
            initiated_by=user,
            mode=mode,
            status=ScanRun.Status.PENDING,
            authorization_verified=active_authorized,
            summary=summary,
        )
        for note in notes:
            write_log(scan_run, "WARNING", note, {"mode_requested": requested_mode, "mode_effective": mode})
        write_log(
            scan_run,
            "INFO",
            "Scan created",
            {
                "mode": mode,
                "requested_mode": requested_mode,
                "specification_id": specification.id if specification else None,
            },
        )
    return scan_run


def select_engines(scan_run):
    log = partial(write_log, scan_run)
    if scan_run.mode == ScanRun.Mode.PASSIVE:
        return [PassiveSpecEngine(scan_run, log)]
    if scan_run.mode == ScanRun.Mode.ACTIVE:
        return [CustomActiveEngine(scan_run, log)]
    if scan_run.mode == ScanRun.Mode.ZAP:
        return [ZapEngine(scan_run, log)]
    return [
        PassiveSpecEngine(scan_run, log),
        CustomActiveEngine(scan_run, log),
        ZapEngine(scan_run, log),
    ]


def persist_findings(scan_run, findings_data):
    rule_ids = {item.rule_id for item in findings_data if item.rule_id}
    rules = {rule.rule_id: rule for rule in ScanRule.objects.filter(rule_id__in=rule_ids)}
    objects = []
    for item in findings_data:
        endpoint = item.endpoint
        if endpoint is not None and endpoint.project_id != scan_run.project_id:
            endpoint = None
        objects.append(
            ScanFinding(
                scan_run=scan_run,
                endpoint=endpoint,
                rule=rules.get(item.rule_id),
                title=item.title,
                description=item.description,
                severity=item.severity,
                confidence=item.confidence,
                owasp_category=item.owasp_category,
                cwe=item.cwe,
                status=ScanFinding.Status.OPEN,
                evidence=item.evidence,
                request=item.request,
                response=item.response,
                remediation=item.remediation,
                verified=item.verified,
                risk_score=item.risk_score,
            )
        )
    return ScanFinding.objects.bulk_create(objects)


def update_counts_and_score(scan_run, findings):
    critical_count = sum(1 for finding in findings if finding.severity == ScanFinding.Severity.CRITICAL)
    high_count = sum(1 for finding in findings if finding.severity == ScanFinding.Severity.HIGH)
    risk_score = max((float(finding.risk_score) for finding in findings), default=0.0)
    scan_run.findings_count = len(findings)
    scan_run.critical_count = critical_count
    scan_run.high_count = high_count
    scan_run.risk_score = round(min(risk_score, 100.0), 2)
    summary = dict(scan_run.summary or {})
    summary.update(
        {
            "finding_counts": {
                "total": len(findings),
                "critical": critical_count,
                "high": high_count,
                "verified": sum(1 for finding in findings if finding.verified),
            },
            "completed_at": timezone.now().isoformat(),
        }
    )
    scan_run.summary = summary
    scan_run.save(
        update_fields=["findings_count", "critical_count", "high_count", "risk_score", "summary", "updated_at"]
    )


def run_scan(scan_run):
    with transaction.atomic():
        scan_run.findings.all().delete()
        scan_run.status = ScanRun.Status.RUNNING
        scan_run.finished_at = None
        scan_run.error_message = ""
        scan_run.endpoints_count = scan_run.project.endpoints.filter(is_active=True).count()
        scan_run.save(update_fields=["status", "finished_at", "error_message", "endpoints_count", "updated_at"])
    write_log(scan_run, "INFO", "Scan started", {"mode": scan_run.mode})

    engines = select_engines(scan_run)
    findings_data = []
    try:
        for engine in engines:
            write_log(scan_run, "INFO", f"Engine {engine.name} started", {"engine": engine.name})
            engine_findings = engine.scan()
            findings_data.extend(engine_findings)
            write_log(
                scan_run,
                "INFO",
                f"Engine {engine.name} completed",
                {"engine": engine.name, "finding_count": len(engine_findings)},
            )
        with transaction.atomic():
            findings = persist_findings(scan_run, findings_data)
            update_counts_and_score(scan_run, findings)
        scan_run.status = ScanRun.Status.COMPLETED
        scan_run.finished_at = timezone.now()
        scan_run.save(update_fields=["status", "finished_at", "updated_at"])
        write_log(
            scan_run,
            "INFO",
            "Scan completed",
            {"findings_count": scan_run.findings_count, "risk_score": scan_run.risk_score},
        )
    except Exception as exc:
        scan_run.status = ScanRun.Status.FAILED
        scan_run.error_message = f"{type(exc).__name__}: {exc}"
        scan_run.finished_at = timezone.now()
        scan_run.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        write_log(scan_run, "ERROR", "Scan failed", {"exception": type(exc).__name__})
    return scan_run
