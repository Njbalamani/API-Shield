import json

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction

from accounts.models import User
from ai_analysis.models import AiAnalysis
from ai_analysis.services import analyze_scan
from api_projects.models import ApiProject, OpenApiSpecification, ScanPolicy
from api_scanner.models import ScanRun
from api_scanner.services import create_scan, run_scan
from authentication_audit.models import AuthenticationAudit
from authentication_audit.services import analyze_project
from endpoint_discovery.models import ApiEndpoint, EndpointParameter
from organizations.models import Organization, OrganizationMembership

LABEL = "SYNTHETIC DEMO DATA"
ORG_SLUG = "apishield-controlled-lab"
PROJECT_SLUG = "apishield-lab-api"
DEMO_EMAIL = "demo@apishield.invalid"
BASE_URL = "https://lab.apishield.invalid"

SPECIFICATION = {
    "openapi": "3.0.3",
    "info": {"title": "Synthetic Lab API", "version": "1.0.0", "description": f"{LABEL}: sample API contract."},
    "servers": [{"url": BASE_URL}],
    "security": [],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "Synthetic token."}
        }
    },
    "paths": {
        "/users/{user_id}": {
            "get": {
                "operationId": "getSyntheticUser",
                "summary": "Synthetic user lookup",
                "tags": ["users"],
                "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic user object"}},
            }
        },
        "/admin/settings": {
            "put": {
                "operationId": "updateSyntheticSettings",
                "summary": "Synthetic administrative update",
                "tags": ["admin"],
                "parameters": [],
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "Synthetic success response"}},
            }
        },
        "/auth/token": {
            "post": {
                "operationId": "issueSyntheticToken",
                "summary": "Synthetic token issuance",
                "tags": ["auth"],
                "parameters": [{"name": "token", "in": "query", "required": False, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic token response"}},
            }
        },
        "/search": {
            "get": {
                "operationId": "searchSyntheticRecords",
                "summary": "Synthetic search",
                "tags": ["search"],
                "parameters": [
                    {"name": "sql", "in": "query", "required": False, "schema": {"type": "string"}},
                    {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "Synthetic results"}},
            }
        },
        "/comments": {
            "get": {
                "operationId": "listSyntheticComments",
                "summary": "Synthetic comments",
                "tags": ["comments"],
                "parameters": [{"name": "html", "in": "query", "required": False, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic comments"}},
            }
        },
        "/billing/invoices": {
            "get": {
                "operationId": "listSyntheticInvoices",
                "summary": "Synthetic invoices",
                "tags": ["billing"],
                "parameters": [{"name": "email", "in": "query", "required": False, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic invoices"}},
            }
        },
    },
}

ENDPOINTS = [
    {
        "path": "/users/{user_id}",
        "method": "GET",
        "operation_id": "getSyntheticUser",
        "summary": "Synthetic user lookup",
        "description": f"{LABEL}: object identifier handled by a controlled lab endpoint.",
        "tags": ["users"],
        "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}],
        "auth_required": False,
        "auth_schemes": [],
        "security": [],
        "risk_level": "high",
    },
    {
        "path": "/admin/settings",
        "method": "PUT",
        "operation_id": "updateSyntheticSettings",
        "summary": "Synthetic administrative update",
        "description": f"{LABEL}: state-changing endpoint used only for passive demonstrations.",
        "tags": ["admin"],
        "parameters": [],
        "request_schema": {"type": "object", "properties": {"email": {"type": "string"}}},
        "auth_required": False,
        "auth_schemes": [],
        "security": [],
        "risk_level": "high",
    },
    {
        "path": "/auth/token",
        "method": "POST",
        "operation_id": "issueSyntheticToken",
        "summary": "Synthetic token issuance",
        "description": f"{LABEL}: token endpoint with an insecure query parameter indicator.",
        "tags": ["auth"],
        "parameters": [{"name": "token", "in": "query", "required": False, "schema": {"type": "string"}}],
        "auth_required": False,
        "auth_schemes": ["jwt"],
        "security": [],
        "risk_level": "high",
    },
    {
        "path": "/search",
        "method": "GET",
        "operation_id": "searchSyntheticRecords",
        "summary": "Synthetic search",
        "description": f"{LABEL}: search endpoint with SQL-related parameter names.",
        "tags": ["search"],
        "parameters": [
            {"name": "sql", "in": "query", "required": False, "schema": {"type": "string"}},
            {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
        ],
        "auth_required": False,
        "auth_schemes": [],
        "security": [],
        "risk_level": "medium",
    },
    {
        "path": "/comments",
        "method": "GET",
        "operation_id": "listSyntheticComments",
        "summary": "Synthetic comments",
        "description": f"{LABEL}: markup-related parameter name for XSS heuristics.",
        "tags": ["comments"],
        "parameters": [{"name": "html", "in": "query", "required": False, "schema": {"type": "string"}}],
        "auth_required": False,
        "auth_schemes": [],
        "security": [],
        "risk_level": "medium",
    },
    {
        "path": "/billing/invoices",
        "method": "GET",
        "operation_id": "listSyntheticInvoices",
        "summary": "Synthetic invoices",
        "description": f"{LABEL}: billing endpoint exposing a sensitive field name.",
        "tags": ["billing"],
        "parameters": [{"name": "email", "in": "query", "required": False, "schema": {"type": "string"}}],
        "response_schema": {"type": "object", "properties": {"email": {"type": "string"}}},
        "auth_required": False,
        "auth_schemes": ["api_key"],
        "security": [],
        "risk_level": "medium",
    },
]


class Command(BaseCommand):
    help = f"Seeds a safe, idempotent {LABEL} environment for APIShield demonstrations."

    def handle(self, *args, **options):
        call_command("seed_rules", verbosity=0)
        with transaction.atomic():
            user = self.demo_user()
            organization = self.organization(user)
            project = self.project(organization, user)
            specification = self.specification(project, user)
            self.endpoints(project, specification)
            scan_run = self.passive_scan(project, user, specification)
            self.label_scan(scan_run)
            self.auth_audit(project, user, scan_run)
            self.ai_analyses(scan_run)
        self.stdout.write(self.style.SUCCESS(f"{LABEL} seeded successfully."))

    def demo_user(self):
        user = User.objects.filter(email=DEMO_EMAIL).first()
        if user is None:
            user = User.objects.create_user(
                username="apishield_demo",
                email=DEMO_EMAIL,
                password=None,
                full_name="APIShield Demo Analyst",
                role=User.Role.ANALYST,
            )
        return user

    def organization(self, user):
        organization, _ = Organization.objects.update_or_create(
            slug=ORG_SLUG,
            defaults={
                "name": "APIShield Controlled Lab",
                "description": f"{LABEL}: isolated organization; no real systems are tested.",
                "is_active": True,
                "created_by": user,
            },
        )
        OrganizationMembership.objects.update_or_create(
            user=user,
            organization=organization,
            defaults={"role": OrganizationMembership.Role.ADMIN, "is_active": True},
        )
        return organization

    def project(self, organization, user):
        project, _ = ApiProject.objects.update_or_create(
            organization=organization,
            slug=PROJECT_SLUG,
            defaults={
                "name": "Synthetic Lab API",
                "description": f"{LABEL}: controlled lab project with a reserved .invalid domain.",
                "environment": ApiProject.Environment.CONTROLLED_LAB,
                "base_url": BASE_URL,
                "authorization_confirmed": False,
                "authorization_reference": "synthetic-lab-authorization",
                "status": ApiProject.Status.ACTIVE,
                "owner": user,
            },
        )
        ScanPolicy.objects.update_or_create(
            project=project,
            defaults={
                "allow_passive_tests": True,
                "allow_active_tests": False,
                "allow_zap": False,
                "max_requests": 10,
                "rate_limit_rpm": 10,
                "timeout_seconds": 5,
                "allowed_hosts": "lab.apishield.invalid",
            },
        )
        return project

    def specification(self, project, user):
        raw_content = json.dumps(SPECIFICATION, indent=2)
        specification, _ = OpenApiSpecification.objects.update_or_create(
            project=project,
            name="Synthetic Lab OpenAPI",
            defaults={
                "version": "1.0.0",
                "source": OpenApiSpecification.Source.PASTED,
                "raw_content": raw_content,
                "parsed_data": SPECIFICATION,
                "endpoint_count": len(SPECIFICATION["paths"]),
                "imported_by": user,
            },
        )
        return specification

    def endpoints(self, project, specification):
        known = set()
        for item in ENDPOINTS:
            endpoint, _ = ApiEndpoint.objects.update_or_create(
                project=project,
                path=item["path"],
                method=item["method"],
                defaults={
                    "specification": specification,
                    "operation_id": item["operation_id"],
                    "summary": item["summary"],
                    "description": item["description"],
                    "tags": item["tags"],
                    "parameters": item["parameters"],
                    "security": item["security"],
                    "request_schema": item.get("request_schema", {}),
                    "response_schema": item.get("response_schema", {}),
                    "auth_required": item["auth_required"],
                    "auth_schemes": item["auth_schemes"],
                    "risk_level": item["risk_level"],
                    "is_active": True,
                },
            )
            known.add(endpoint.id)
            for parameter in item["parameters"]:
                EndpointParameter.objects.update_or_create(
                    endpoint=endpoint,
                    name=parameter["name"],
                    location=parameter["in"],
                    defaults={
                        "required": bool(parameter.get("required")),
                        "schema": parameter.get("schema", {}),
                        "sensitive": parameter["name"] in {"token", "email"},
                    },
                )
        project.endpoints.exclude(id__in=known).delete()

    def passive_scan(self, project, user, specification):
        scan_run = (
            ScanRun.objects.filter(project=project, mode=ScanRun.Mode.PASSIVE, summary__synthetic=True)
            .order_by("-started_at")
            .first()
        )
        if scan_run is not None and scan_run.findings.exists():
            return scan_run
        if scan_run is None:
            scan_run = create_scan(project, user, ScanRun.Mode.PASSIVE, specification=specification)
            summary = dict(scan_run.summary or {})
            summary["synthetic"] = True
            scan_run.summary = summary
            scan_run.save(update_fields=["summary"])
        run_scan(scan_run)
        return scan_run

    def label_scan(self, scan_run):
        if scan_run is None:
            return
        scan_run.findings.update(is_synthetic=True)
        summary = dict(scan_run.summary or {})
        summary["synthetic"] = True
        notes = list(summary.get("notes", []))
        label_note = f"{LABEL}: findings were generated from synthetic endpoints on a reserved .invalid domain."
        if label_note not in notes:
            notes.append(label_note)
        summary["notes"] = notes
        scan_run.summary = summary
        scan_run.save(update_fields=["summary"])

    def auth_audit(self, project, user, scan_run):
        analyze_project(project, user=user, scan_run=scan_run)
        audits = AuthenticationAudit.objects.filter(project=project, scan_run=scan_run)
        for audit in audits:
            findings = list(audit.findings or [])
            label = f"{LABEL}: authentication checks were generated from synthetic endpoints."
            if not any(label in str(item.get("message", "")) for item in findings if isinstance(item, dict)):
                findings.append({"code": "SYNTHETIC", "severity": "info", "message": label, "evidence": {}})
                audit.findings = findings
                audit.save(update_fields=["findings"])

    def ai_analyses(self, scan_run):
        if scan_run is None:
            return
        analyze_scan(scan_run)
        for analysis in AiAnalysis.objects.filter(finding__scan_run=scan_run):
            if analysis.explanation.startswith(LABEL):
                continue
            analysis.explanation = f"{LABEL}: {analysis.explanation}"
            analysis.save(update_fields=["explanation"])
