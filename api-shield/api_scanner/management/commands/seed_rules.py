from django.core.management.base import BaseCommand

from api_scanner.models import ScanRule

RULES = [
    {
        "rule_id": "PS-BOLA-001",
        "title": "Object identifier handled without confirmed ownership checks",
        "description": (
            "Heuristic indicator for broken object level authorization based on identifiers in paths and parameters."
        ),
        "category": "Authorization",
        "severity": ScanRule.Severity.HIGH,
        "confidence": "medium",
        "owasp_category": "API1:2023 - Broken Object Level Authorization",
        "cwe": "CWE-639",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Enforce object-level authorization on every request.",
            "steps": [
                "Resolve the object through the authenticated principal",
                "Return 404 for unauthorized identifiers",
                "Add automated ownership tests",
            ],
        },
    },
    {
        "rule_id": "PS-AUTH-002",
        "title": "Authentication requirement is missing or incomplete",
        "description": "Heuristic indicator that an operation lacks a declared authentication scheme or scope.",
        "category": "Authentication",
        "severity": ScanRule.Severity.HIGH,
        "confidence": "medium",
        "owasp_category": "API2:2023 - Broken Authentication",
        "cwe": "CWE-287",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Require and validate authentication for all protected operations.",
            "steps": [
                "Declare security requirements in the API contract",
                "Reject missing or invalid credentials",
                "Rotate exposed credentials",
            ],
        },
    },
    {
        "rule_id": "PS-BFLA-003",
        "title": "State-changing operation lacks documented function-level authorization",
        "description": "Heuristic indicator for broken function level authorization on write operations.",
        "category": "Authorization",
        "severity": ScanRule.Severity.HIGH,
        "confidence": "medium",
        "owasp_category": "API5:2023 - Broken Function Level Authorization",
        "cwe": "CWE-862",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Check user role and scope before every state change.",
            "steps": ["Map operations to required roles", "Deny by default", "Test privilege boundaries"],
        },
    },
    {
        "rule_id": "PS-SQLI-004",
        "title": "Parameter names suggest SQL query construction",
        "description": "Heuristic indicator based on SQL-related parameter names in the API contract.",
        "category": "Injection",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API8:2019 - Injection",
        "cwe": "CWE-89",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Use parameterized queries and strict allowlists.",
            "steps": [
                "Replace string-built SQL with bound parameters",
                "Validate sort and filter fields against allowlists",
                "Minimize database privileges",
            ],
        },
    },
    {
        "rule_id": "PS-XSS-005",
        "title": "Parameters may carry untrusted markup or URLs",
        "description": "Heuristic indicator for cross-site scripting based on markup-related parameter names.",
        "category": "Injection",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API8:2019 - Injection",
        "cwe": "CWE-79",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Encode untrusted output and validate redirect targets.",
            "steps": [
                "Apply context-aware output encoding",
                "Use an allowlist for redirect URLs",
                "Set a restrictive Content Security Policy",
            ],
        },
    },
    {
        "rule_id": "PS-MISCONF-006",
        "title": "Security misconfiguration indicator",
        "description": (
            "Heuristic indicator from missing specification metadata, plaintext transport, or incomplete "
            "operation documentation."
        ),
        "category": "Configuration",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API8:2023 - Security Misconfiguration",
        "cwe": "CWE-16",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Harden configuration and keep API documentation complete.",
            "steps": [
                "Require TLS",
                "Remove unnecessary methods and headers",
                "Document every operation and security scheme",
            ],
        },
    },
    {
        "rule_id": "PS-RATELIMIT-007",
        "title": "No rate-limiting control is documented",
        "description": (
            "Heuristic indicator that resource-consuming or sensitive operations do not document throttling."
        ),
        "category": "Resource Management",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
        "cwe": "CWE-770",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Apply rate limits and request size limits.",
            "steps": [
                "Throttle per principal and per IP",
                "Bound pagination and payload sizes",
                "Return 429 with Retry-After",
            ],
        },
    },
    {
        "rule_id": "PS-DATA-008",
        "title": "Sensitive data fields are present in the operation contract",
        "description": "Heuristic indicator based on field names associated with sensitive data.",
        "category": "Data Exposure",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API3:2019 - Excessive Data Exposure",
        "cwe": "CWE-200",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Minimize response fields and protect sensitive values.",
            "steps": ["Return only required fields", "Mask sensitive values", "Encrypt secrets at rest"],
        },
    },
    {
        "rule_id": "PS-VALIDATION-009",
        "title": "Input constraints are not documented",
        "description": "Heuristic indicator that parameter schemas or request constraints are missing.",
        "category": "Input Validation",
        "severity": ScanRule.Severity.MEDIUM,
        "confidence": "low",
        "owasp_category": "API3:2023 - Broken Object Property Level Authorization",
        "cwe": "CWE-20",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Validate all input against explicit schemas.",
            "steps": ["Define types and length limits", "Reject unknown properties", "Use allowlists for enumerations"],
        },
    },
    {
        "rule_id": "AA-JWT-010",
        "title": "Token expiration is not documented",
        "description": "Authentication audit check for token lifetime and refresh guidance.",
        "category": "Authentication",
        "severity": "low",
        "confidence": "medium",
        "owasp_category": "API2:2023 - Broken Authentication",
        "cwe": "CWE-613",
        "engine": ScanRule.Engine.AUTH,
        "remediation": {
            "summary": "Document and enforce short token lifetimes.",
            "steps": ["Set exp claims", "Rotate refresh tokens", "Revoke tokens on logout"],
        },
    },
    {
        "rule_id": "AA-TRANSPORT-011",
        "title": "Insecure token handling indicator",
        "description": "Authentication audit check for tokens in query strings, cookies, or plaintext transport.",
        "category": "Authentication",
        "severity": "high",
        "confidence": "medium",
        "owasp_category": "API2:2023 - Broken Authentication",
        "cwe": "CWE-522",
        "engine": ScanRule.Engine.AUTH,
        "remediation": {
            "summary": "Transport tokens only in secure headers over TLS.",
            "steps": ["Use Authorization headers", "Set Secure and HttpOnly cookie flags", "Remove tokens from URLs"],
        },
    },
    {
        "rule_id": "CA-REFLECT-013",
        "title": "Unique probe marker reflected by the target",
        "description": (
            "Direct evidence that a unique marker supplied in a safe GET or HEAD probe was reflected in the response."
        ),
        "category": "Injection",
        "severity": "high",
        "confidence": "high",
        "owasp_category": "API8:2019 - Injection",
        "cwe": "CWE-79",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Apply context-aware output encoding to reflected values.",
            "steps": [
                "Encode response data for its output context",
                "Validate accepted characters",
                "Set a restrictive Content Security Policy",
            ],
        },
    },
    {
        "rule_id": "CA-HEADERS-014",
        "title": "Security response headers are missing",
        "description": "Limited active check for absent defensive response headers on safe requests.",
        "category": "Configuration",
        "severity": "low",
        "confidence": "low",
        "owasp_category": "API8:2023 - Security Misconfiguration",
        "cwe": "CWE-693",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Add standard defensive response headers.",
            "steps": ["Set X-Content-Type-Options", "Set X-Frame-Options", "Deploy a Content Security Policy"],
        },
    },
    {
        "rule_id": "ZAP-ALERT-015",
        "title": "OWASP ZAP alert",
        "description": "Alert reported by an authorized OWASP ZAP integration.",
        "category": "External Scanner",
        "severity": "medium",
        "confidence": "low",
        "owasp_category": "API8:2023 - Security Misconfiguration",
        "cwe": "CWE-1035",
        "engine": ScanRule.Engine.ZAP,
        "remediation": {
            "summary": "Review the ZAP alert and remediate the underlying issue.",
            "steps": [
                "Confirm the affected parameter",
                "Apply framework-level controls",
                "Re-run the authorized assessment",
            ],
        },
    },
    {
        "rule_id": "PS-INVENTORY-012",
        "title": "Endpoint inventory metadata is incomplete",
        "description": "Heuristic indicator that inventory metadata is insufficient for inventory management reviews.",
        "category": "Inventory",
        "severity": "low",
        "confidence": "low",
        "owasp_category": "API9:2023 - Improper Inventory Management",
        "cwe": "CWE-1059",
        "engine": ScanRule.Engine.CUSTOM,
        "remediation": {
            "summary": "Maintain a complete API inventory.",
            "steps": ["Register every environment", "Track deprecation dates", "Remove undocumented endpoints"],
        },
    },
]


class Command(BaseCommand):
    help = "Seeds APIShield scan rules with OWASP categories and CWE labels."

    def handle(self, *args, **options):
        created = 0
        updated = 0
        for rule_data in RULES:
            _, was_created = ScanRule.objects.update_or_create(rule_id=rule_data["rule_id"], defaults=rule_data)
            if was_created:
                created += 1
            else:
                updated += 1
        self.stdout.write(
            self.style.SUCCESS(f"Scan rules ready: {created} created, {updated} updated, {len(RULES)} total.")
        )
