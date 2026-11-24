from urllib.parse import urlparse

from endpoint_discovery.models import EndpointParameter

from .models import AuthenticationAudit, TokenTest

JWT_TERMS = ("jwt", "bearer", "jsonwebtoken", "json_web_token")
OAUTH_TERMS = ("oauth", "openid", "authorization_code", "client_credentials", "implicit")
API_KEY_TERMS = ("api_key", "apikey", "api-key", "x-api-key")
BASIC_TERMS = ("basic", "basicauth", "basic_auth")
EXPIRATION_TERMS = ("expire", "expiration", "expires_in", "lifetime", "ttl", "refresh", "exp claim", "max_age")
INSECURE_TERMS = ("localstorage", "query string", "querystring", "url parameter", "plaintext", "http://")
SENSITIVE_PATH_TERMS = ("auth", "token", "password", "admin", "billing", "payment", "secret", "session")
SENSITIVE_PARAM_TERMS = ("token", "api_key", "apikey", "api-key", "password", "secret", "session")


def _flatten(value):
    if value is None:
        return []
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            result.append(str(key))
            result.extend(_flatten(item))
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for item in value:
            result.extend(_flatten(item))
        return result
    return [str(value)]


def security_strings(endpoint, specification):
    values = _flatten(endpoint.auth_schemes)
    values.extend(_flatten(endpoint.security))
    values.extend(_flatten(endpoint.description))
    if specification is not None and isinstance(specification.parsed_data, dict):
        components = specification.parsed_data.get("components", {})
        if isinstance(components, dict):
            values.extend(_flatten(components.get("securitySchemes", {})))
        values.extend(_flatten(specification.parsed_data.get("security")))
    return [value.lower().replace("-", "_") for value in values if value is not None]


def detect_auth_type(values):
    blob = " ".join(values)
    if any(term in blob for term in JWT_TERMS):
        return AuthenticationAudit.AuthType.JWT
    if any(term in blob for term in OAUTH_TERMS):
        return AuthenticationAudit.AuthType.OAUTH2
    if any(term in blob for term in API_KEY_TERMS):
        return AuthenticationAudit.AuthType.API_KEY
    if any(term in blob for term in BASIC_TERMS):
        return AuthenticationAudit.AuthType.BASIC
    if "none" in blob or not blob.strip():
        return AuthenticationAudit.AuthType.NONE
    return AuthenticationAudit.AuthType.UNKNOWN


def parameter_locations(endpoint):
    locations = []
    for parameter in endpoint.parameters or []:
        if isinstance(parameter, dict):
            locations.append((str(parameter.get("name", "")), str(parameter.get("in", "")).lower()))
    for parameter in EndpointParameter.objects.filter(endpoint=endpoint):
        locations.append((parameter.name, parameter.location))
    return locations


def evaluate_endpoint(endpoint, user=None, scan_run=None, specification=None):
    values = security_strings(endpoint, specification)
    blob = " ".join(values)
    auth_type = detect_auth_type(values)
    path = str(endpoint.path or "")
    method = str(endpoint.method or "").upper()
    locations = parameter_locations(endpoint)
    global_security = bool(
        specification and isinstance(specification.parsed_data, dict) and specification.parsed_data.get("security")
    )
    scheme_in_query = False
    if specification and isinstance(specification.parsed_data, dict):
        components = specification.parsed_data.get("components", {})
        if isinstance(components, dict):
            schemes = components.get("securitySchemes", {})
            if isinstance(schemes, dict):
                scheme_in_query = any(
                    isinstance(scheme, dict) and str(scheme.get("in", "")).lower() == "query"
                    for scheme in schemes.values()
                )
    credentials_in_query = [
        name
        for name, location in locations
        if location == "query" and any(term in name.lower() for term in SENSITIVE_PARAM_TERMS)
    ]
    base_scheme = urlparse(str(endpoint.project.base_url or "")).scheme.lower()
    expiration_detected = any(term in blob for term in EXPIRATION_TERMS)
    insecure_token_handling = bool(
        scheme_in_query or credentials_in_query or base_scheme == "http" or any(term in blob for term in INSECURE_TERMS)
    )
    authorization_controls = bool(
        endpoint.auth_required or endpoint.security or endpoint.auth_schemes or global_security
    )
    sensitive_path = any(term in path.lower() for term in SENSITIVE_PATH_TERMS)

    findings = []
    if auth_type == AuthenticationAudit.AuthType.NONE:
        findings.append(
            {
                "code": "AUTH-SCHEME-MISSING",
                "severity": "fail" if sensitive_path else "warn",
                "message": "No authentication scheme was detected for the operation.",
                "evidence": {"path": path, "method": method, "auth_required": bool(endpoint.auth_required)},
            }
        )
    if auth_type in {AuthenticationAudit.AuthType.JWT, AuthenticationAudit.AuthType.OAUTH2} and not expiration_detected:
        findings.append(
            {
                "code": "TOKEN-EXPIRATION-UNDOCUMENTED",
                "severity": "warn",
                "message": "Token expiration and refresh behavior are not documented.",
                "evidence": {"path": path, "method": method, "auth_type": auth_type},
            }
        )
    if insecure_token_handling:
        findings.append(
            {
                "code": "TOKEN-HANDLING-INSECURE",
                "severity": "fail",
                "message": "Token handling indicators show credentials in query data or insecure transport.",
                "evidence": {
                    "path": path,
                    "method": method,
                    "credentials_in_query": credentials_in_query,
                    "scheme_in_query": scheme_in_query,
                    "transport": base_scheme,
                },
            }
        )
    if not authorization_controls:
        findings.append(
            {
                "code": "AUTHORIZATION-CONTROLS-MISSING",
                "severity": "fail",
                "message": "No documented authorization controls were found for the operation.",
                "evidence": {"path": path, "method": method, "sensitive_path": sensitive_path},
            }
        )
    if auth_type == AuthenticationAudit.AuthType.UNKNOWN:
        findings.append(
            {
                "code": "AUTH-SCHEME-UNKNOWN",
                "severity": "warn",
                "message": "The authentication scheme could not be classified from available metadata.",
                "evidence": {"path": path, "method": method},
            }
        )

    score = 100.0
    for finding in findings:
        if finding["severity"] == "fail":
            score -= 35
        elif finding["severity"] == "warn":
            score -= 12
    score = max(0.0, min(100.0, score))
    if any(finding["severity"] == "fail" for finding in findings):
        result = AuthenticationAudit.Result.FAIL
    elif findings:
        result = AuthenticationAudit.Result.WARN
    else:
        result = AuthenticationAudit.Result.PASS
    return {
        "auth_type": auth_type,
        "result": result,
        "expiration_detected": expiration_detected,
        "insecure_token_handling": insecure_token_handling,
        "authorization_controls": authorization_controls,
        "findings": findings,
        "score": round(score, 2),
        "schemes_detected": sorted(set(values)),
    }


def create_token_tests(audit, evaluation):
    tests = [
        (
            "Authentication scheme detection",
            "pass" if evaluation["auth_type"] != AuthenticationAudit.AuthType.NONE else "warn",
            {"auth_type": evaluation["auth_type"], "schemes_detected": evaluation["schemes_detected"][:20]},
        ),
        (
            "Token expiration documentation",
            "pass" if evaluation["expiration_detected"] else "warn",
            {"expiration_detected": evaluation["expiration_detected"]},
        ),
        (
            "Token transport and storage",
            "fail" if evaluation["insecure_token_handling"] else "pass",
            {"insecure_token_handling": evaluation["insecure_token_handling"]},
        ),
        (
            "Authorization control coverage",
            "pass" if evaluation["authorization_controls"] else "fail",
            {"authorization_controls": evaluation["authorization_controls"]},
        ),
    ]
    audit.token_tests.all().delete()
    TokenTest.objects.bulk_create(
        [TokenTest(audit=audit, name=name, outcome=outcome, evidence=evidence) for name, outcome, evidence in tests]
    )
    return len(tests)


def analyze_endpoint(endpoint, user=None, scan_run=None, specification=None):
    if specification is None:
        specification = endpoint.specification or endpoint.project.specifications.order_by("-imported_at").first()
    evaluation = evaluate_endpoint(endpoint, specification)
    audit_fields = {
        "auth_type",
        "result",
        "expiration_detected",
        "insecure_token_handling",
        "authorization_controls",
        "findings",
        "score",
    }
    defaults = {key: value for key, value in evaluation.items() if key in audit_fields}
    audit, _ = AuthenticationAudit.objects.update_or_create(
        organization=endpoint.project.organization,
        project=endpoint.project,
        scan_run=scan_run,
        endpoint=endpoint,
        defaults=defaults,
    )
    create_token_tests(audit, evaluation)
    return audit


def analyze_project(project, user=None, scan_run=None, endpoints=None):
    queryset = endpoints if endpoints is not None else project.endpoints.filter(is_active=True)
    specification = scan_run.specification if scan_run is not None and scan_run.specification_id else None
    if specification is None:
        specification = project.specifications.order_by("-imported_at").first()
    if hasattr(queryset, "select_related"):
        queryset = queryset.select_related("specification", "project")
    endpoint_list = list(queryset)
    audits = []
    if not endpoint_list:
        evaluation = evaluate_endpoint_project(project, specification)
        audit, _ = AuthenticationAudit.objects.update_or_create(
            organization=project.organization,
            project=project,
            scan_run=scan_run,
            endpoint=None,
            defaults=evaluation,
        )
        create_token_tests(audit, evaluation)
        audits.append(audit)
    else:
        for endpoint in endpoint_list:
            audit = analyze_endpoint(endpoint, user=user, scan_run=scan_run, specification=specification)
            audits.append(audit)
    result_counts = {}
    auth_types = {}
    for audit in audits:
        result_counts[audit.result] = result_counts.get(audit.result, 0) + 1
        auth_types[audit.auth_type] = auth_types.get(audit.auth_type, 0) + 1
    token_tests = sum(audit.token_tests.count() for audit in audits)
    return {
        "project_id": project.id,
        "audits_created": len(audits),
        "token_tests_created": token_tests,
        "result_counts": result_counts,
        "auth_types": auth_types,
        "average_score": round(sum(audit.score for audit in audits) / len(audits), 2) if audits else 0.0,
    }


def evaluate_endpoint_project(project, specification):
    values = security_strings_from_specification(specification)
    auth_type = detect_auth_type(values)
    expiration_detected = any(term in " ".join(values) for term in EXPIRATION_TERMS)
    authorization_controls = bool(
        specification and isinstance(specification.parsed_data, dict) and specification.parsed_data.get("security")
    )
    findings = []
    if auth_type == AuthenticationAudit.AuthType.NONE:
        findings.append(
            {
                "code": "AUTH-SCHEME-MISSING",
                "severity": "warn",
                "message": "No authentication scheme was detected in the project specification.",
                "evidence": {"project": project.name},
            }
        )
    if not authorization_controls:
        findings.append(
            {
                "code": "AUTHORIZATION-CONTROLS-MISSING",
                "severity": "fail",
                "message": "No global authorization controls were found.",
                "evidence": {"project": project.name},
            }
        )
    score = 100.0 - sum(35 if item["severity"] == "fail" else 12 for item in findings)
    result = (
        AuthenticationAudit.Result.FAIL
        if any(item["severity"] == "fail" for item in findings)
        else AuthenticationAudit.Result.WARN
        if findings
        else AuthenticationAudit.Result.PASS
    )
    return {
        "auth_type": auth_type,
        "result": result,
        "expiration_detected": expiration_detected,
        "insecure_token_handling": False,
        "authorization_controls": authorization_controls,
        "findings": findings,
        "score": max(0.0, min(100.0, score)),
    }


def security_strings_from_specification(specification):
    if specification is None or not isinstance(specification.parsed_data, dict):
        return []
    values = _flatten(specification.parsed_data.get("security"))
    components = specification.parsed_data.get("components", {})
    if isinstance(components, dict):
        values.extend(_flatten(components.get("securitySchemes", {})))
    return [value.lower().replace("-", "_") for value in values if value is not None]


def run_auth_audit(project, user=None, scan_run=None, endpoints=None):
    return analyze_project(project, user=user, scan_run=scan_run, endpoints=endpoints)
