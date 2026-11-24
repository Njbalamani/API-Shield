import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.test import APIRequestFactory

from accounts.authentication import ApiKeyAuthentication
from accounts.models import ApiKey, LoginAttempt, User
from accounts.permissions import (
    HasOrganizationRole,
    IsAdminRole,
    IsAnalystRole,
    OrganizationRoleRequiredMixin,
    has_minimum_role,
    user_organizations,
)
from accounts.services import clear_login_failures, create_api_key, login_user, register_user, revoke_api_key
from ai_analysis.models import AiAnalysis
from ai_analysis.services import analyze_finding
from api_projects.models import ApiProject, OpenApiSpecification, ScanPolicy
from api_projects.services import confirm_authorization, create_project
from api_scanner.models import ScanFinding, ScanRun
from api_scanner.services import assess_active_authorization, create_scan, run_scan
from authentication_audit.models import AuthenticationAudit
from authentication_audit.services import run_auth_audit
from behaviour_monitor.models import ApiRequestLog, BehaviourAlert
from behaviour_monitor.services import analyse_request_log, record_request
from config.exception_handler import api_exception_handler
from dashboard.services import get_metrics
from endpoint_discovery.models import ApiEndpoint, EndpointParameter
from endpoint_discovery.services import import_openapi_spec
from organizations.middleware import OrganizationContextMiddleware
from organizations.models import Organization, OrganizationMembership
from organizations.services import switch_organization
from reports.models import Report
from reports.services import create_report
from vulnerability_manager.models import VerificationRecord, VulnerabilityAssignment
from vulnerability_manager.services import assign_finding, verify_assignment

settings.MIGRATION_MODULES = {
    "accounts": None,
    "organizations": None,
    "api_projects": None,
    "endpoint_discovery": None,
    "api_scanner": None,
    "authentication_audit": None,
    "behaviour_monitor": None,
    "vulnerability_manager": None,
    "ai_analysis": None,
    "reports": None,
    "dashboard": None,
}

TEST_PASSWORD = "A-long-test-password-123"


def with_test_settings(test_class):
    return override_settings(TESTING=True)(test_class)


def make_user(email=None, role=User.Role.ANALYST, **overrides):
    token = uuid4().hex[:10]
    values = {"username": f"user-{token}", "full_name": f"User {token}", "role": role}
    values.update(overrides)
    return User.objects.create_user(
        email=email or f"{token}@example.test",
        password=TEST_PASSWORD,
        **values,
    )


def make_organization(name="Acme API", creator=None, **overrides):
    values = {"slug": uuid4().hex[:12], "created_by": creator}
    values.update(overrides)
    return Organization.objects.create(name=name, **values)


def add_membership(user, organization, role):
    return OrganizationMembership.objects.create(user=user, organization=organization, role=role)


def make_project(organization, owner, name="Payments API", **overrides):
    values = {"slug": uuid4().hex[:12]}
    values.update(overrides)
    return create_project(organization=organization, owner=owner, name=name, **values)


def sample_spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Sample API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {
            "/users/{user_id}": {
                "get": {
                    "operationId": "getUser",
                    "summary": "Get a user",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "verbose",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "boolean"},
                        },
                    ],
                    "responses": {"200": {"description": "OK"}},
                },
                "delete": {
                    "operationId": "deleteUser",
                    "summary": "Delete a user",
                    "security": [{"bearerAuth": []}],
                    "responses": {"204": {"description": "Deleted"}},
                },
            }
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }


def unauthenticated_spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Unauthenticated API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {
            "/admin/tokens": {
                "get": {
                    "operationId": "listTokens",
                    "summary": "List tokens",
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }


def import_spec(project, imported_by, document=None):
    return import_openapi_spec(
        project=project,
        content=json.dumps(document or sample_spec()),
        imported_by=imported_by,
    )


def make_passive_scan(project, specification, initiated_by):
    scan_run = create_scan(project, initiated_by, ScanRun.Mode.PASSIVE, specification=specification)
    return run_scan(scan_run)


class Handler:
    def dispatch(self, request, *args, **kwargs):
        return "allowed"


class AnalystProtectedView(OrganizationRoleRequiredMixin, Handler):
    required_role = "analyst"


@with_test_settings
class AccountAndOrganizationTests(TestCase):
    def test_registration_creates_user_and_owner_membership(self):
        email = f"registered-{uuid4().hex[:10]}@example.test"
        username = f"registered-{uuid4().hex[:10]}"
        user, organization = register_user(
            email=email,
            username=username,
            full_name="Registered Owner",
            password=TEST_PASSWORD,
            organization_name="Owner Org",
        )
        membership = OrganizationMembership.objects.get(user=user, organization=organization)
        self.assertTrue(user.check_password(TEST_PASSWORD))
        self.assertEqual(user.role, User.Role.ADMIN)
        self.assertEqual(membership.role, OrganizationMembership.Role.ADMIN)
        self.assertEqual(organization.created_by, user)
        self.assertTrue(has_minimum_role(user, organization, "admin"))
        self.assertIn(organization, user_organizations(user))

    def test_login_service_records_success_and_failure(self):
        email = f"attempts-{uuid4().hex[:10]}@example.test"
        ip_address = "127.0.0.1"
        clear_login_failures(email, ip_address)
        user = make_user(email=email)
        request = RequestFactory().post("/accounts/login/", REMOTE_ADDR=ip_address)
        failed_user, failed_reason = login_user(request=request, email=email, password="wrong-password")
        self.assertIsNone(failed_user)
        self.assertEqual(failed_reason, "invalid")
        success_user, success_reason = login_user(request=request, email=email, password=TEST_PASSWORD)
        self.assertEqual(success_user, user)
        self.assertIsNone(success_reason)
        attempts = list(LoginAttempt.objects.filter(email=email).order_by("created_at"))
        self.assertEqual(len(attempts), 2)
        self.assertFalse(attempts[0].success)
        self.assertTrue(attempts[1].success)
        clear_login_failures(email, ip_address)

    def test_organization_switch_uses_active_membership_and_falls_back(self):
        user = make_user()
        first = make_organization(name="Alpha Org", creator=user)
        second = make_organization(name="Beta Org", creator=user)
        other = make_organization(name="Other Org")
        add_membership(user, first, OrganizationMembership.Role.VIEWER)
        add_membership(user, second, OrganizationMembership.Role.ANALYST)
        selected = switch_organization(user=user, organization_id=second.pk)
        self.assertEqual(selected, second)
        with self.assertRaises(PermissionDenied):
            switch_organization(user=user, organization_id=other.pk)
        middleware = OrganizationContextMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/dashboard/")
        request.user = user
        request.session = {"active_organization_id": str(second.id)}
        middleware(request)
        self.assertEqual(request.current_organization, second)
        self.assertEqual(request.current_role, OrganizationMembership.Role.ANALYST)
        request.session = {"active_organization_id": "99999999"}
        middleware(request)
        self.assertEqual(request.current_organization, first)
        self.assertEqual(request.current_role, OrganizationMembership.Role.VIEWER)


@with_test_settings
class ProjectAndSpecificationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.organization = make_organization(creator=self.user)
        add_membership(self.user, self.organization, OrganizationMembership.Role.ANALYST)

    def test_project_creation_creates_safe_scan_policy(self):
        project = make_project(self.organization, self.user)
        policy = ScanPolicy.objects.get(project=project)
        self.assertEqual(project.environment, ApiProject.Environment.CONTROLLED_LAB)
        self.assertFalse(project.authorization_confirmed)
        self.assertFalse(policy.allow_active_tests)
        self.assertFalse(policy.allow_zap)
        self.assertTrue(policy.allow_passive_tests)
        self.assertEqual(policy.max_requests, 40)
        self.assertEqual(policy.rate_limit_rpm, 30)
        self.assertEqual(policy.timeout_seconds, 15)

    def test_openapi_import_creates_endpoints_and_parameters(self):
        project = make_project(self.organization, self.user)
        specification = import_spec(project, self.user)
        self.assertEqual(specification.parsed_data["spec_type"], "openapi3")
        self.assertEqual(specification.parsed_data["endpoint_count"], 2)
        self.assertEqual(specification.endpoint_count, 2)
        self.assertEqual(project.endpoints.count(), 2)
        self.assertEqual(OpenApiSpecification.objects.filter(project=project).count(), 1)
        endpoint = ApiEndpoint.objects.get(project=project, method="GET")
        self.assertTrue(endpoint.auth_required)
        self.assertEqual(endpoint.operation_id, "getUser")
        self.assertEqual(endpoint.endpoint_parameters.count(), 2)
        self.assertTrue(endpoint.endpoint_parameters.filter(name="user_id", required=True).exists())
        self.assertTrue(endpoint.endpoint_parameters.filter(name="verbose", location="query").exists())
        self.assertEqual(EndpointParameter.objects.filter(endpoint=endpoint).count(), 2)


@with_test_settings
class ScanningTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.organization = make_organization(creator=self.user)
        add_membership(self.user, self.organization, OrganizationMembership.Role.ANALYST)
        self.project = make_project(self.organization, self.user)
        self.specification = import_spec(self.project, self.user)

    def test_passive_scan_creates_findings_with_verified_false(self):
        scan_run = make_passive_scan(self.project, self.specification, self.user)
        findings = list(scan_run.findings.all())
        self.assertEqual(scan_run.mode, ScanRun.Mode.PASSIVE)
        self.assertEqual(scan_run.status, ScanRun.Status.COMPLETED)
        self.assertGreater(len(findings), 0)
        self.assertTrue(all(finding.verified is False for finding in findings))
        self.assertTrue(all(finding.status == ScanFinding.Status.OPEN for finding in findings))
        self.assertEqual(scan_run.findings_count, len(findings))
        self.assertGreater(scan_run.risk_score, 0)
        self.assertTrue(scan_run.logs.filter(message="Passive analysis completed").exists())

    def test_active_scan_downgrades_when_authorization_is_missing(self):
        self.project.base_url = "https://lab-api.internal"
        self.project.save(update_fields=["base_url", "updated_at"])
        policy = self.project.scan_policy
        policy.allow_active_tests = True
        policy.allowed_hosts = "lab-api.internal"
        policy.save(update_fields=["allow_active_tests", "allowed_hosts"])
        with patch.dict(settings.APISHIELD, {"ACTIVE_TESTING_ENABLED": True}):
            authorization = assess_active_authorization(self.project)
            scan_run = create_scan(self.project, self.user, ScanRun.Mode.ACTIVE)
        self.assertFalse(authorization["allowed"])
        self.assertIn("project authorization has not been confirmed", authorization["reasons"])
        self.assertEqual(scan_run.mode, ScanRun.Mode.PASSIVE)
        self.assertFalse(scan_run.authorization_verified)
        self.assertEqual(scan_run.summary["mode_requested"], ScanRun.Mode.ACTIVE)
        self.assertEqual(scan_run.summary["mode_effective"], ScanRun.Mode.PASSIVE)
        self.assertFalse(scan_run.summary["active_testing_performed"])
        warning = scan_run.logs.filter(level="WARNING").first()
        self.assertIsNotNone(warning)
        self.assertIn("downgraded", warning.message)

    def test_authorized_active_scan_uses_requested_mode(self):
        project = make_project(
            self.organization,
            self.user,
            name="Authorized API",
            base_url="https://lab-api.internal",
            authorization_confirmed=True,
            authorization_reference="ENG-2026-1124",
        )
        confirm_authorization(project=project, reference="ENG-2026-1124")
        policy = project.scan_policy
        policy.allow_active_tests = True
        policy.save(update_fields=["allow_active_tests"])
        with patch.dict(settings.APISHIELD, {"ACTIVE_TESTING_ENABLED": True}):
            scan_run = create_scan(project, self.user, ScanRun.Mode.ACTIVE)
        self.assertEqual(scan_run.mode, ScanRun.Mode.ACTIVE)
        self.assertTrue(scan_run.authorization_verified)
        self.assertTrue(scan_run.summary["active_testing_performed"])
        self.assertEqual(scan_run.summary["authorization"]["hostname"], "lab-api.internal")

    def test_authentication_audit_service_evaluates_declared_schemes(self):
        specification = import_spec(self.project, self.user, unauthenticated_spec())
        summary = run_auth_audit(self.project, user=self.user)
        audit = AuthenticationAudit.objects.get(endpoint__path="/admin/tokens")
        self.assertEqual(summary["audits_created"], self.project.endpoints.count())
        self.assertEqual(summary["token_tests_created"], self.project.endpoints.count() * 4)
        self.assertEqual(audit.auth_type, AuthenticationAudit.AuthType.NONE)
        self.assertEqual(audit.result, AuthenticationAudit.Result.FAIL)
        self.assertFalse(audit.authorization_controls)
        self.assertEqual(audit.token_tests.count(), 4)
        self.assertIsNotNone(specification)

    def test_ai_analysis_service_uses_local_source_without_network(self):
        scan_run = make_passive_scan(self.project, self.specification, self.user)
        finding = scan_run.findings.first()
        with (
            patch.dict(settings.APISHIELD, {"AI_EXPLANATIONS_ENABLED": False, "GEMINI_API_KEY": ""}),
            patch("ai_analysis.services.requests.post", side_effect=AssertionError("unexpected network call")),
        ):
            analysis = analyze_finding(finding)
        self.assertEqual(analysis.source, AiAnalysis.Source.LOCAL)
        self.assertTrue(analysis.model_name.startswith("local-risk-model"))
        self.assertGreater(analysis.risk_score, 0)
        self.assertEqual(analysis.finding, finding)
        self.assertEqual(AiAnalysis.objects.filter(organization=self.organization).count(), 1)


@with_test_settings
class MonitoringAndRemediationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.organization = make_organization(creator=self.user)
        add_membership(self.user, self.organization, OrganizationMembership.Role.ANALYST)
        self.project = make_project(self.organization, self.user)
        self.specification = import_spec(self.project, self.user)

    def test_dashboard_metrics_derived_from_database(self):
        scan_run = make_passive_scan(self.project, self.specification, self.user)
        finding = scan_run.findings.first()
        assignment, _ = assign_finding(
            finding,
            self.organization,
            assignee=self.user,
            assigned_by=self.user,
            notes="Remediation started",
        )
        verify_assignment(
            assignment,
            self.user,
            result=VerificationRecord.Result.VERIFIED_FIXED,
            notes="Re-tested in controlled lab",
            evidence={"status": 200},
        )
        with patch.dict(
            settings.APISHIELD,
            {
                "BEHAVIOUR_WINDOW_MINUTES": 10,
                "REQUEST_FREQUENCY_THRESHOLD": 3,
                "FAILED_REQUEST_THRESHOLD": 1,
                "SENSITIVE_PATH_TERMS": ["admin", "token"],
            },
        ):
            logs = [
                record_request(
                    organization=self.organization,
                    project=self.project,
                    method="GET",
                    path="/items",
                    ip_address="127.0.0.1",
                    status_code=500,
                    response_time_ms=40,
                    query_keys=[],
                )
                for _ in range(3)
            ]
            analyse_request_log(logs[0])
        metrics = get_metrics(self.organization)
        self.assertEqual(metrics["total_projects"], 1)
        self.assertEqual(metrics["total_endpoints"], self.project.endpoints.count())
        self.assertEqual(metrics["total_scans"], 1)
        self.assertEqual(metrics["completed_scans"], 1)
        self.assertEqual(metrics["total_vulnerabilities"], ScanFinding.objects.filter(scan_run=scan_run).count())
        self.assertEqual(metrics["verified_findings"], 1)
        self.assertGreaterEqual(metrics["api_risk_score"], 0)
        self.assertGreaterEqual(metrics["alert_count"], 1)
        self.assertEqual(metrics["trend_days"], 7)

    def test_vulnerability_assignment_and_verification(self):
        scan_run = make_passive_scan(self.project, self.specification, self.user)
        finding = scan_run.findings.first()
        assignment, created = assign_finding(
            finding,
            self.organization,
            assignee=self.user,
            assigned_by=self.user,
            status=VulnerabilityAssignment.Status.FIXED,
            priority=VulnerabilityAssignment.Priority.URGENT,
            notes="Rate limit implemented",
        )
        verification = verify_assignment(
            assignment,
            self.user,
            result=VerificationRecord.Result.VERIFIED_FIXED,
            notes="Re-tested in controlled lab",
            evidence={"status": 200},
        )
        finding.refresh_from_db()
        assignment.refresh_from_db()
        self.assertTrue(created)
        self.assertEqual(finding.assignment, assignment)
        self.assertEqual(assignment.priority, VulnerabilityAssignment.Priority.URGENT)
        self.assertEqual(assignment.status, VulnerabilityAssignment.Status.CLOSED)
        self.assertEqual(finding.status, ScanFinding.Status.RESOLVED)
        self.assertTrue(finding.verified)
        self.assertEqual(assignment.verifications.count(), 1)
        self.assertEqual(verification.result, VerificationRecord.Result.VERIFIED_FIXED)
        self.assertEqual(verification.evidence["evidence"], {"status": 200})

    def test_behaviour_alerts_created_by_service_thresholds(self):
        with patch.dict(
            settings.APISHIELD,
            {
                "BEHAVIOUR_WINDOW_MINUTES": 10,
                "REQUEST_FREQUENCY_THRESHOLD": 3,
                "FAILED_REQUEST_THRESHOLD": 1,
                "SENSITIVE_PATH_TERMS": [],
            },
        ):
            logs = []
            for index in range(3):
                logs.append(
                    record_request(
                        organization=self.organization,
                        project=self.project,
                        method="GET",
                        path="/items",
                        ip_address="127.0.0.1",
                        status_code=500 if index == 0 else 200,
                        response_time_ms=40,
                        query_keys=[],
                    )
                )
            alerts = analyse_request_log(logs[0])
        self.assertEqual(
            {alert.alert_type for alert in alerts},
            {
                BehaviourAlert.AlertType.HIGH_FREQUENCY,
                BehaviourAlert.AlertType.REPEATED_FAILURES,
            },
        )
        self.assertTrue(all(alert.organization == self.organization for alert in alerts))
        self.assertEqual(BehaviourAlert.objects.filter(project=self.project).count(), 2)
        self.assertTrue(ApiRequestLog.objects.filter(project=self.project, is_suspicious=True).exists())


@with_test_settings
class ReportingTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.organization = make_organization(creator=self.user)
        add_membership(self.user, self.organization, OrganizationMembership.Role.ANALYST)
        self.project = make_project(self.organization, self.user)

    def test_pdf_and_json_report_generation(self):
        with tempfile.TemporaryDirectory() as media_root:
            reports_root = Path(media_root) / "reports"
            with override_settings(MEDIA_ROOT=media_root, REPORTS_ROOT=reports_root):
                pdf_report = create_report(
                    self.organization,
                    self.project,
                    created_by=self.user,
                    report_type=Report.ReportType.FULL,
                    file_format=Report.FileFormat.PDF,
                )
                self.assertEqual(pdf_report.status, Report.Status.COMPLETED)
                self.assertTrue(pdf_report.file.name.endswith(".pdf"))
                self.assertTrue(Path(pdf_report.file.path).exists())
                self.assertTrue(Path(pdf_report.file.path).read_bytes().startswith(b"%PDF"))

                json_report = create_report(
                    self.organization,
                    self.project,
                    created_by=self.user,
                    report_type=Report.ReportType.OWASP,
                    file_format=Report.FileFormat.JSON,
                    parameters={"owasp_only": True},
                )
                self.assertEqual(json_report.status, Report.Status.COMPLETED)
                payload = json.loads(Path(json_report.file.path).read_text(encoding="utf-8"))
                self.assertEqual(payload["metadata"]["project"]["id"], self.project.id)
                self.assertEqual(payload["metadata"]["report"]["parameters"], {"owasp_only": True})
                self.assertEqual(Report.objects.filter(organization=self.organization).count(), 2)


@with_test_settings
class ApiKeyTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.organization = make_organization(creator=self.user)
        add_membership(self.user, self.organization, OrganizationMembership.Role.ADMIN)

    def test_api_key_creation_authentication_and_revocation(self):
        api_key, raw_key = create_api_key(
            user=self.user,
            organization=self.organization,
            name="CI integration",
        )
        self.assertTrue(raw_key.startswith("apishield_"))
        self.assertEqual(api_key.prefix, raw_key[:16])
        self.assertEqual(api_key.key_hash, ApiKey.hash_key(raw_key))
        self.assertNotEqual(api_key.key_hash, raw_key)
        authentication = ApiKeyAuthentication()
        request = APIRequestFactory().get("/", HTTP_X_API_KEY=raw_key)
        now = timezone.now()
        with patch("django.utils.timezone.now", return_value=now):
            authenticated_user, token = authentication.authenticate(request)
        self.assertEqual(authenticated_user, self.user)
        self.assertEqual(token["api_key"], api_key)
        self.assertEqual(request.current_organization, self.organization)
        self.assertEqual(request.current_role, "api_key")
        api_key.refresh_from_db()
        self.assertEqual(api_key.last_used_at, now)
        revoked = revoke_api_key(api_key=api_key, user=self.user)
        self.assertFalse(revoked.is_active)
        self.assertIsNotNone(revoked.revoked_at)
        with self.assertRaises(AuthenticationFailed):
            authentication.authenticate(APIRequestFactory().get("/", HTTP_X_API_KEY=raw_key))


@with_test_settings
class RbacAndErrorTests(TestCase):
    def setUp(self):
        self.user = make_user(role=User.Role.VIEWER)
        self.organization = make_organization(creator=self.user)
        self.membership = add_membership(self.user, self.organization, OrganizationMembership.Role.VIEWER)
        self.request = RequestFactory().get("/api/projects/")
        self.request.user = self.user
        self.request.current_organization = self.organization
        self.request.request_id = "rbac-test-request"

    def test_viewer_role_is_denied_for_analyst_and_admin_operations(self):
        self.assertFalse(has_minimum_role(self.user, self.organization, "analyst"))
        self.assertFalse(IsAnalystRole().has_permission(self.request, None))
        self.assertFalse(IsAdminRole().has_permission(self.request, None))
        self.assertTrue(HasOrganizationRole().has_permission(self.request, None))
        with self.assertRaises(PermissionDenied):
            AnalystProtectedView().dispatch(self.request)
        self.membership.role = OrganizationMembership.Role.ANALYST
        self.membership.save(update_fields=["role"])
        self.assertEqual(AnalystProtectedView().dispatch(self.request), "allowed")
        self.assertTrue(has_minimum_role(self.user, self.organization, "analyst"))
        self.assertFalse(has_minimum_role(self.user, self.organization, "admin"))

    def test_exception_handler_returns_standard_error_envelope(self):
        response = api_exception_handler(ValidationError({"detail": "bad request"}), {"request": self.request})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error"]["code"], "http_400")
        self.assertEqual(response.data["error"]["message"], "bad request")
        self.assertEqual(response.data["error"]["request_id"], "rbac-test-request")
