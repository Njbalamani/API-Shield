import re
import secrets
import time
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings

from endpoint_discovery.models import EndpointParameter

from .base import BaseScanEngine, RuleMixin, ScanFindingData, compute_risk_score, normalize_confidence, sanitize_text

PASSIVE_CONFIDENCE = ("low", "medium")

SENSITIVE_TERMS = (
    "admin",
    "auth",
    "token",
    "password",
    "secret",
    "payment",
    "billing",
    "api-key",
    "api_key",
    "credit",
    "ssn",
)

IDENTIFIER_TERMS = (
    "id",
    "user_id",
    "account_id",
    "order_id",
    "customer_id",
    "uuid",
    "guid",
    "resource",
)

SQL_TERMS = (
    "sql",
    "query",
    "sort",
    "order",
    "filter",
    "where",
    "search",
    "limit",
    "offset",
    "column",
    "table",
)

XSS_TERMS = (
    "xss",
    "html",
    "comment",
    "message",
    "description",
    "content",
    "callback",
    "redirect",
    "url",
    "display_name",
)

DATA_TERMS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "ssn",
    "credit_card",
    "card_number",
    "email",
    "phone",
    "date_of_birth",
    "dob",
)

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD"}
PROBE_PARAMETER = "_apishield_probe"


def parse_hosts(raw_hosts):
    return {item.strip().lower() for item in str(raw_hosts or "").split(",") if item.strip()}


def endpoint_parameter_names(endpoint):
    names = []
    for parameter in endpoint.parameters or []:
        if isinstance(parameter, dict) and parameter.get("name"):
            names.append(str(parameter["name"]))
    for parameter in EndpointParameter.objects.filter(endpoint=endpoint):
        names.append(parameter.name)
    return list(dict.fromkeys(names))


def response_property_names(endpoint):
    names = []
    for section in (endpoint.response_schema or {}, endpoint.request_schema or {}):
        properties = section.get("properties", {}) if isinstance(section, dict) else {}
        if isinstance(properties, dict):
            names.extend(str(name) for name in properties)
    return names


def contains_term(name, terms):
    normalized = str(name or "").lower().replace("-", "_")
    return [term for term in terms if term in normalized]


class PassiveSpecEngine(RuleMixin, BaseScanEngine):
    name = "passive"

    def scan(self):
        endpoints = list(self.scoped_endpoints())
        specification = self.scan_run.specification or self.project.specifications.order_by("-imported_at").first()
        self.log("INFO", "Passive analysis started", {"endpoint_count": len(endpoints)})
        findings = self.analyze_specification(specification, endpoints)
        for endpoint in endpoints:
            findings.extend(self.analyze_endpoint(endpoint, specification))
        self.log("INFO", "Passive analysis completed", {"finding_count": len(findings)})
        return findings

    def scoped_endpoints(self):
        queryset = self.project.endpoints.filter(is_active=True).select_related("specification")
        if self.scan_run.specification_id:
            queryset = queryset.filter(specification_id=self.scan_run.specification_id)
        return queryset

    def analyze_specification(self, specification, endpoints):
        findings = []
        parsed = specification.parsed_data if specification and isinstance(specification.parsed_data, dict) else {}
        components = parsed.get("components", {}) if isinstance(parsed.get("components", {}), dict) else {}
        schemes = components.get("securitySchemes", {})
        if not isinstance(schemes, dict):
            schemes = {}
        raw_text = str(specification.raw_content or "") if specification else ""

        if not specification:
            findings.append(
                self.passive_finding(
                    "PS-MISCONF-006",
                    title="No API specification is associated with the scan",
                    description=(
                        "Passive analysis could not confirm declared security schemes because no specification "
                        "was supplied."
                    ),
                    evidence={"project": self.project.name, "reason": "specification_missing"},
                    severity="low",
                    confidence="low",
                )
            )
        else:
            if not schemes and not parsed.get("security"):
                findings.append(
                    self.passive_finding(
                        "PS-MISCONF-006",
                        title="Specification does not declare security schemes",
                        description=(
                            "The specification has no global security requirement and no reusable security schemes."
                        ),
                        evidence={"specification": specification.name, "security_schemes": sorted(schemes)},
                    )
                )
            if not parsed.get("servers"):
                findings.append(
                    self.passive_finding(
                        "PS-MISCONF-006",
                        title="Specification does not declare servers",
                        description=(
                            "No server entries were found, so transport and host assumptions cannot be validated."
                        ),
                        evidence={"specification": specification.name, "reason": "servers_missing"},
                        severity="low",
                        confidence="low",
                    )
                )
            if "http://" in raw_text.lower():
                findings.append(
                    self.passive_finding(
                        "PS-MISCONF-006",
                        title="Specification references plaintext HTTP transport",
                        description=(
                            "A server URL uses plaintext HTTP, which can expose credentials and tokens in transit."
                        ),
                        evidence={"specification": specification.name, "transport": "http"},
                    )
                )
            if not any(endpoint.security for endpoint in endpoints) and endpoints:
                findings.append(
                    self.passive_finding(
                        "PS-AUTH-002",
                        title="Operations do not declare security requirements",
                        description="No analysed operation declares an OpenAPI security requirement.",
                        evidence={"endpoint_count": len(endpoints), "reason": "operation_security_missing"},
                    )
                )
            if "rate" not in raw_text.lower() and "limit" not in raw_text.lower():
                findings.append(
                    self.passive_finding(
                        "PS-RATELIMIT-007",
                        title="Specification does not document rate limiting",
                        description=(
                            "No rate-limit hints were found in the specification for resource-consuming operations."
                        ),
                        evidence={"specification": specification.name, "reason": "rate_limit_hint_missing"},
                        severity="low",
                        confidence="low",
                    )
                )
        return findings

    def analyze_endpoint(self, endpoint, specification):
        findings = []
        path = str(endpoint.path or "")
        path_lower = path.lower()
        method = str(endpoint.method or "").upper()
        parameter_names = endpoint_parameter_names(endpoint)
        all_names = parameter_names + response_property_names(endpoint)
        security_present = bool(endpoint.security or endpoint.auth_schemes or endpoint.auth_required)
        global_security = bool(
            specification and isinstance(specification.parsed_data, dict) and specification.parsed_data.get("security")
        )
        sensitive_path = bool(contains_term(path_lower, SENSITIVE_TERMS))
        path_identifiers = re.findall(r"\{([^}]+)\}", path)
        identifier_parameters = [name for name in parameter_names if contains_term(name, IDENTIFIER_TERMS)]

        if path_identifiers or identifier_parameters:
            exposed = not security_present and not global_security
            findings.append(
                self.passive_finding(
                    "PS-BOLA-001",
                    endpoint=endpoint,
                    title="Object identifier handled without confirmed ownership checks",
                    description=(
                        "The operation accepts an object identifier. Documentation does not demonstrate "
                        "that object-level authorization is enforced, which is a BOLA indicator requiring "
                        "manual review."
                    ),
                    evidence={
                        "path": path,
                        "method": method,
                        "path_identifiers": path_identifiers,
                        "identifier_parameters": identifier_parameters,
                        "auth_required": bool(endpoint.auth_required),
                        "security_declared": security_present or global_security,
                    },
                    severity="high" if exposed else "medium",
                    confidence="medium" if exposed else "low",
                )
            )

        if not security_present and not global_security:
            findings.append(
                self.passive_finding(
                    "PS-AUTH-002",
                    endpoint=endpoint,
                    title="No authentication requirement is documented for this operation",
                    description="The endpoint has no declared authentication scheme or required security scope.",
                    evidence={
                        "path": path,
                        "method": method,
                        "auth_required": bool(endpoint.auth_required),
                        "auth_schemes": endpoint.auth_schemes or [],
                        "sensitive_path": sensitive_path,
                    },
                    severity="high" if sensitive_path else "medium",
                    confidence="medium",
                )
            )
        elif endpoint.auth_required and not endpoint.auth_schemes and not endpoint.security:
            findings.append(
                self.passive_finding(
                    "PS-AUTH-002",
                    endpoint=endpoint,
                    title="Authentication is marked required without a declared scheme",
                    description=(
                        "The operation is marked as authenticated but does not identify how credentials are supplied."
                    ),
                    evidence={"path": path, "method": method, "reason": "scheme_missing"},
                    severity="medium",
                    confidence="low",
                )
            )

        if method in WRITE_METHODS and (not security_present or (sensitive_path and not endpoint.security)):
            findings.append(
                self.passive_finding(
                    "PS-BFLA-003",
                    endpoint=endpoint,
                    title="State-changing operation lacks documented function-level authorization",
                    description="A write operation does not document role or scope checks, which is a BFLA indicator.",
                    evidence={
                        "path": path,
                        "method": method,
                        "security": endpoint.security or [],
                        "auth_required": bool(endpoint.auth_required),
                        "sensitive_path": sensitive_path,
                    },
                    severity="high" if sensitive_path else "medium",
                    confidence="medium" if not security_present else "low",
                )
            )

        sql_indicators = sorted({term for name in parameter_names for term in contains_term(name, SQL_TERMS)})
        if sql_indicators:
            findings.append(
                self.passive_finding(
                    "PS-SQLI-004",
                    endpoint=endpoint,
                    title="Parameter names suggest SQL query construction",
                    description=(
                        "Parameter names include terms commonly used in SQL query building and warrant manual review."
                    ),
                    evidence={
                        "path": path,
                        "method": method,
                        "parameters": parameter_names,
                        "indicators": sql_indicators,
                    },
                    severity="medium",
                    confidence="low",
                )
            )

        xss_indicators = sorted({term for name in all_names for term in contains_term(name, XSS_TERMS)})
        if xss_indicators:
            findings.append(
                self.passive_finding(
                    "PS-XSS-005",
                    endpoint=endpoint,
                    title="Parameters may carry untrusted markup or URLs",
                    description=(
                        "Parameter names contain XSS-adjacent terms; output encoding must be verified manually."
                    ),
                    evidence={"path": path, "method": method, "parameters": all_names, "indicators": xss_indicators},
                    severity="medium",
                    confidence="low",
                )
            )

        if not endpoint.tags or not (endpoint.summary or endpoint.description):
            findings.append(
                self.passive_finding(
                    "PS-MISCONF-006",
                    endpoint=endpoint,
                    title="Operation metadata is incomplete",
                    description=(
                        "Missing tags and descriptions reduce auditability and may indicate an unmaintained "
                        "API surface."
                    ),
                    evidence={"path": path, "method": method, "tags": endpoint.tags or []},
                    severity="low",
                    confidence="low",
                )
            )

        if sensitive_path or method in WRITE_METHODS or any(term in path_lower for term in ("login", "session")):
            findings.append(
                self.passive_finding(
                    "PS-RATELIMIT-007",
                    endpoint=endpoint,
                    title="No rate-limiting control is documented for this operation",
                    description="Sensitive or state-changing operations should document throttling and abuse controls.",
                    evidence={"path": path, "method": method, "sensitive_path": sensitive_path},
                    severity="medium" if sensitive_path else "low",
                    confidence="low",
                )
            )

        data_indicators = sorted({term for name in all_names for term in contains_term(name, DATA_TERMS)})
        if data_indicators:
            findings.append(
                self.passive_finding(
                    "PS-DATA-008",
                    endpoint=endpoint,
                    title="Sensitive data fields are present in the operation contract",
                    description=(
                        "The operation exposes fields associated with sensitive data and needs "
                        "data-minimization review."
                    ),
                    evidence={"path": path, "method": method, "fields": all_names, "indicators": data_indicators},
                    severity="medium",
                    confidence="low",
                )
            )

        unconstrained = [
            name
            for name in parameter_names
            if not any(
                isinstance(parameter, dict)
                and parameter.get("name") == name
                and (isinstance(parameter.get("schema"), dict) and parameter.get("schema"))
                for parameter in (endpoint.parameters or [])
            )
        ]
        if unconstrained or (method in WRITE_METHODS and not endpoint.request_schema):
            findings.append(
                self.passive_finding(
                    "PS-VALIDATION-009",
                    endpoint=endpoint,
                    title="Input constraints are not documented",
                    description=(
                        "Parameter schemas or request constraints are missing, indicating inconsistent "
                        "input validation."
                    ),
                    evidence={
                        "path": path,
                        "method": method,
                        "unconstrained_parameters": unconstrained,
                        "request_schema_present": bool(endpoint.request_schema),
                    },
                    severity="medium" if method in WRITE_METHODS else "low",
                    confidence="low",
                )
            )
        return findings

    def passive_finding(self, rule_id, *, endpoint=None, evidence=None, **overrides):
        values = self.rule_values(rule_id, **overrides)
        confidence = normalize_confidence(values["confidence"], allowed=PASSIVE_CONFIDENCE)
        severity = values["severity"]
        return ScanFindingData(
            title=values["title"],
            description=values["description"],
            severity=severity,
            confidence=confidence,
            owasp_category=values["owasp_category"],
            cwe=values["cwe"],
            endpoint=endpoint,
            rule_id=rule_id,
            evidence=evidence or {},
            request={},
            response={},
            remediation=values["remediation"],
            verified=False,
            risk_score=compute_risk_score(severity, confidence, False),
        )


class CustomActiveEngine(RuleMixin, BaseScanEngine):
    name = "custom-active"
    SAFE_METHODS = SAFE_METHODS

    def scan(self):
        policy = getattr(self.project, "scan_policy", None)
        config = settings.APISHIELD
        reasons = []
        if policy is None or not policy.allow_active_tests:
            reasons.append("scan policy does not permit active tests")
        if not config.get("ACTIVE_TESTING_ENABLED"):
            reasons.append("active testing is disabled globally")
        if not self.scan_run.authorization_verified:
            reasons.append("active authorization was not verified for this scan")
        if reasons:
            self.log("WARNING", "Active testing skipped", {"reasons": reasons})
            return []

        base_url = str(self.project.base_url or "").strip()
        parsed_base = urlparse(base_url)
        hostname = (parsed_base.hostname or "").lower()
        allowed_hosts = parse_hosts(policy.allowed_hosts)
        if parsed_base.scheme not in {"http", "https"} or not hostname or hostname not in allowed_hosts:
            self.log("WARNING", "Active testing skipped for unapproved target", {"hostname": hostname})
            return []

        endpoints = list(
            self.project.endpoints.filter(is_active=True, method__in=sorted(self.SAFE_METHODS)).order_by(
                "path", "method"
            )
        )
        max_requests = min(
            max(1, int(policy.max_requests or config.get("MAX_ACTIVE_REQUESTS", 40))),
            max(1, int(config.get("MAX_ACTIVE_REQUESTS", 40))),
        )
        rpm = min(
            max(1, int(policy.rate_limit_rpm or config.get("SCAN_RATE_LIMIT_RPM", 30))),
            max(1, int(config.get("SCAN_RATE_LIMIT_RPM", 30))),
        )
        timeout = min(
            max(1, int(policy.timeout_seconds or config.get("SCAN_TIMEOUT_SECONDS", 15))),
            max(1, int(config.get("SCAN_TIMEOUT_SECONDS", 15))),
        )
        delay = 60.0 / rpm
        findings = []
        self.log(
            "INFO",
            "Controlled active probing started",
            {"endpoint_count": len(endpoints), "max_requests": max_requests, "rate_limit_rpm": rpm},
        )
        for index, endpoint in enumerate(endpoints[:max_requests]):
            if index:
                time.sleep(delay)
            findings.extend(self.probe(endpoint, base_url, allowed_hosts, timeout))
        self.log("INFO", "Controlled active probing completed", {"finding_count": len(findings)})
        return findings

    def probe(self, endpoint, base_url, allowed_hosts, timeout):
        method = str(endpoint.method or "").upper()
        if method not in self.SAFE_METHODS:
            return []
        path = re.sub(r"\{[^}]+\}", "1", str(endpoint.path or "")).lstrip("/")
        target = urljoin(base_url.rstrip("/") + "/", path)
        if urlparse(target).hostname not in allowed_hosts:
            return []
        marker = f"apishield-{secrets.token_hex(8)}"
        request_evidence = {
            "method": method,
            "path": path,
            "query_keys": [PROBE_PARAMETER],
            "probe_name": PROBE_PARAMETER,
        }
        try:
            response = requests.request(
                method,
                target,
                params={PROBE_PARAMETER: marker},
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "APIShield-ControlledProbe/1.0",
                    "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
                },
            )
        except requests.RequestException as exc:
            self.log("WARNING", "Active probe failed", {"path": path, "exception": type(exc).__name__})
            return []
        if (urlparse(response.url).hostname or "").lower() not in allowed_hosts:
            self.log("WARNING", "Active probe redirected outside approved hosts", {"path": path})
            return []

        response_evidence = {
            "status_code": int(response.status_code),
            "content_type": str(response.headers.get("Content-Type", ""))[:120],
            "content_length": len(response.content or b""),
            "reflected": False,
            "reflection_location": "",
        }
        reflected_in_body = method == "GET" and marker in response.text
        reflected_in_header = any(marker in str(value) for value in response.headers.values())
        if reflected_in_body or reflected_in_header:
            response_evidence["reflected"] = True
            response_evidence["reflection_location"] = "body" if reflected_in_body else "header"
            if reflected_in_body:
                index = response.text.find(marker)
                excerpt = response.text[max(0, index - 80) : index + len(marker) + 80]
                response_evidence["body_excerpt"] = sanitize_text(excerpt.replace(marker, "[MARKER]"))

        findings = []
        if response_evidence["reflected"]:
            values = self.rule_values("CA-REFLECT-013")
            findings.append(
                ScanFindingData(
                    title=values["title"],
                    description=values["description"],
                    severity=values["severity"],
                    confidence=values["confidence"],
                    owasp_category=values["owasp_category"],
                    cwe=values["cwe"],
                    endpoint=endpoint,
                    rule_id="CA-REFLECT-013",
                    evidence={"unique_marker_reflected": True, "path": path, "method": method},
                    request=request_evidence,
                    response=response_evidence,
                    remediation=values["remediation"],
                    verified=True,
                )
            )

        header_names = {"x-content-type-options", "x-frame-options", "content-security-policy"}
        security_headers = {name.lower() for name in response.headers if name.lower() in header_names}
        if len(security_headers) < 2:
            values = self.rule_values("CA-HEADERS-014")
            findings.append(
                ScanFindingData(
                    title=values["title"],
                    description=values["description"],
                    severity=values["severity"],
                    confidence=values["confidence"],
                    owasp_category=values["owasp_category"],
                    cwe=values["cwe"],
                    endpoint=endpoint,
                    rule_id="CA-HEADERS-014",
                    evidence={"present_headers": sorted(security_headers), "path": path, "method": method},
                    request=request_evidence,
                    response=response_evidence,
                    remediation=values["remediation"],
                    verified=False,
                )
            )
        return findings
