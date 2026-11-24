import json
from collections.abc import Mapping

import yaml
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count

from api_projects.models import OpenApiSpecification

from .models import ApiEndpoint, EndpointParameter

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_TERMS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api-key",
    "apikey",
    "api_key",
    "authorization",
    "credential",
    "session",
    "cookie",
    "login",
    "signin",
    "sign-in",
    "logout",
    "otp",
    "ssn",
    "credit",
    "card",
    "private-key",
    "private_key",
}
MAX_SPEC_BYTES = 10 * 1024 * 1024
MAX_ENDPOINTS = 2000


def _as_mapping(value):
    return value if isinstance(value, Mapping) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _text(value):
    if value is None:
        return ""
    return str(value).strip()


def _is_sensitive(value):
    lowered = (value or "").lower()
    configured = {
        str(term).strip().lower() for term in getattr(settings, "APISHIELD", {}).get("SENSITIVE_PATH_TERMS", [])
    }
    return any(term and term in lowered for term in SENSITIVE_TERMS | configured)


def _resolve_ref(document, node, depth=0):
    if not isinstance(node, Mapping) or depth > 8:
        return node
    reference = node.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return node
    current = document
    try:
        for token in reference[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, Mapping):
                return {key: value for key, value in node.items() if key != "$ref"}
            current = current[token]
    except (KeyError, TypeError):
        return {key: value for key, value in node.items() if key != "$ref"}
    if isinstance(current, Mapping) and "$ref" in current and current["$ref"] != reference:
        return _resolve_ref(document, current, depth + 1)
    return current


def parse_spec_content(content, *, filename=""):
    if isinstance(content, bytes):
        if len(content) > MAX_SPEC_BYTES:
            raise ValidationError("The specification file is too large.")
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValidationError("The specification must be UTF-8 encoded text.") from exc
    else:
        text = str(content or "")
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise ValidationError("The specification content is too large.")
    text = text.lstrip("\ufeff").strip()
    if not text:
        raise ValidationError("The specification content is empty.")
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            label = f" in {filename}" if filename else ""
            raise ValidationError(f"Unable to parse the specification{label} as JSON or YAML.") from exc
    if not isinstance(document, Mapping):
        raise ValidationError("The specification must be a JSON or YAML object.")
    return dict(document)


def validate_spec_document(document):
    openapi_version = _text(document.get("openapi"))
    swagger_version = _text(document.get("swagger"))
    if openapi_version.startswith("3."):
        return "openapi3"
    if swagger_version.startswith("2."):
        return "swagger2"
    raise ValidationError("Only OpenAPI 3.x and Swagger 2.x documents are supported.")


def _schema_summary(document, schema, depth=0):
    raw = schema
    reference = _text(raw.get("$ref")) if isinstance(raw, Mapping) else ""
    resolved = _resolve_ref(document, raw)
    if not isinstance(resolved, Mapping):
        return {"ref": reference} if reference else {}
    summary = {}
    schema_type = _text(resolved.get("type"))
    if schema_type:
        summary["type"] = schema_type
    if resolved.get("format"):
        summary["format"] = _text(resolved["format"])
    properties = _as_mapping(resolved.get("properties"))
    if properties and depth < 3:
        summary["properties"] = {
            str(name): _schema_summary(document, value, depth + 1) for name, value in properties.items()
        }
    required = [str(value) for value in _as_list(resolved.get("required"))]
    if required:
        summary["required"] = required
    if "items" in resolved and depth < 3:
        summary["items"] = _schema_summary(document, resolved["items"], depth + 1)
    enum = [str(value) for value in _as_list(resolved.get("enum"))[:20]]
    if enum:
        summary["enum"] = enum
    if resolved.get("nullable"):
        summary["nullable"] = True
    if reference:
        summary["ref"] = reference
    return summary


def _normalize_parameters(document, raw_parameters, spec_type):
    result = []
    for raw in _as_list(raw_parameters):
        item = _resolve_ref(document, raw)
        if not isinstance(item, Mapping):
            continue
        name = _text(item.get("name"))
        location = _text(item.get("in")).lower()
        if spec_type == "swagger2" and location == "formdata":
            location = "body"
        if not name or location not in EndpointParameter.Location.values:
            continue
        if "schema" in item:
            schema = _schema_summary(document, item.get("schema"))
        elif "content" in item:
            content = _as_mapping(item.get("content"))
            media = content.get("application/json") or (next(iter(content.values()), None) if content else None)
            schema = _schema_summary(document, _as_mapping(media).get("schema"))
        else:
            schema = _schema_summary(document, item)
        example = item.get("example") or item.get("x-example") or ""
        if isinstance(example, (dict, list)):
            example = json.dumps(example, sort_keys=True)
        result.append(
            {
                "name": name,
                "location": location,
                "required": bool(item.get("required", False)),
                "schema": schema,
                "example": _text(example)[:500],
                "sensitive": _is_sensitive(name),
                "description": _text(item.get("description"))[:500],
            }
        )
    return result


def _request_body_summary(document, operation, spec_type):
    if spec_type == "swagger2":
        for raw in _as_list(operation.get("parameters")):
            item = _resolve_ref(document, raw)
            if isinstance(item, Mapping) and _text(item.get("in")).lower() == "body":
                consumes = _as_list(operation.get("consumes")) or _as_list(document.get("consumes"))
                return {
                    "content_type": _text(consumes[0]) if consumes else "application/json",
                    "schema": _schema_summary(document, item.get("schema")),
                    "required": bool(item.get("required", False)),
                }
        return {}
    request_body = _resolve_ref(document, operation.get("requestBody"))
    if not isinstance(request_body, Mapping):
        return {}
    content = _as_mapping(request_body.get("content"))
    if not content:
        return {}
    content_type = "application/json" if "application/json" in content else next(iter(content))
    media = _as_mapping(content.get(content_type))
    return {
        "content_type": content_type,
        "schema": _schema_summary(document, media.get("schema")),
        "required": bool(request_body.get("required", False)),
    }


def _response_summary(document, operation, spec_type):
    responses = {}
    for status_code, raw in _as_mapping(operation.get("responses")).items():
        response = _resolve_ref(document, raw)
        if not isinstance(response, Mapping):
            continue
        entry = {"description": _text(response.get("description"))[:300]}
        if spec_type == "swagger2":
            produces = _as_list(operation.get("produces")) or _as_list(document.get("produces"))
            entry["content_type"] = _text(produces[0]) if produces else "application/json"
            if "schema" in response:
                entry["schema"] = _schema_summary(document, response["schema"])
        else:
            content = _as_mapping(response.get("content"))
            if content:
                content_type = "application/json" if "application/json" in content else next(iter(content))
                entry["content_type"] = content_type
                entry["schema"] = _schema_summary(document, _as_mapping(content.get(content_type)).get("schema"))
            headers = _as_mapping(response.get("headers"))
            if headers:
                entry["headers"] = [str(name) for name in headers]
        responses[str(status_code)] = entry
    return responses


def _security_schemes(document, spec_type):
    if spec_type == "openapi3":
        raw = _as_mapping(_as_mapping(document.get("components")).get("securitySchemes"))
    else:
        raw = _as_mapping(document.get("securityDefinitions"))
    result = {}
    for name, definition in raw.items():
        resolved = _resolve_ref(document, definition)
        result[str(name)] = dict(resolved) if isinstance(resolved, Mapping) else {}
    return result


def _security_info(document, operation, global_security, schemes):
    requirements = operation.get("security", global_security)
    if requirements is None:
        requirements = global_security
    parsed = []
    for requirement in _as_list(requirements):
        if isinstance(requirement, str):
            parsed.append(
                {"scheme": requirement, "scopes": [], "type": _text(_as_mapping(schemes.get(requirement)).get("type"))}
            )
            continue
        if not isinstance(requirement, Mapping):
            continue
        for scheme_name, scopes in requirement.items():
            definition = _as_mapping(schemes.get(str(scheme_name)))
            parsed.append(
                {
                    "scheme": str(scheme_name),
                    "scopes": [str(scope) for scope in _as_list(scopes)],
                    "type": _text(definition.get("type")) or "unknown",
                    "in": _text(definition.get("in")),
                    "name": _text(definition.get("name")),
                }
            )
    return parsed, bool(parsed)


def _risk_level(path, method, auth_required, parameters, operation):
    score = 0
    if not auth_required:
        score += 3
    if method in WRITE_METHODS:
        score += 2
    if "admin" in (path or "").lower():
        score += 2
    if _is_sensitive(path):
        score += 1
    if any(parameter.get("sensitive") for parameter in parameters):
        score += 1
    if any(
        parameter.get("sensitive") and parameter.get("location") in {"query", "header", "cookie"}
        for parameter in parameters
    ):
        score += 2
    if method == "DELETE":
        score += 1
    if operation.get("deprecated"):
        score += 1
    if score >= 7:
        return ApiEndpoint.RiskLevel.CRITICAL
    if score >= 5:
        return ApiEndpoint.RiskLevel.HIGH
    if score >= 3:
        return ApiEndpoint.RiskLevel.MEDIUM
    if score >= 1:
        return ApiEndpoint.RiskLevel.LOW
    return ApiEndpoint.RiskLevel.NONE


def normalize_spec(document):
    spec_type = validate_spec_document(document)
    info = _as_mapping(document.get("info"))
    schemes = _security_schemes(document, spec_type)
    global_security = _as_list(document.get("security"))
    endpoints = []
    for raw_path, raw_item in _as_mapping(document.get("paths")).items():
        path = _text(raw_path)
        if not path:
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        item = _resolve_ref(document, raw_item)
        if not isinstance(item, Mapping):
            continue
        path_parameters = _normalize_parameters(document, item.get("parameters"), spec_type)
        for method, raw_operation in item.items():
            method_name = _text(method).upper()
            if method_name not in HTTP_METHODS:
                continue
            operation = _resolve_ref(document, raw_operation)
            if not isinstance(operation, Mapping):
                continue
            parameters = []
            seen = set()
            for parameter in path_parameters + _normalize_parameters(document, operation.get("parameters"), spec_type):
                key = (parameter["name"], parameter["location"])
                if key in seen:
                    continue
                seen.add(key)
                parameters.append(parameter)
            body = _request_body_summary(document, operation, spec_type)
            if body:
                parameters.append(
                    {
                        "name": "body",
                        "location": "body",
                        "required": bool(body.get("required")),
                        "schema": body.get("schema", {}),
                        "example": "",
                        "sensitive": False,
                        "description": "",
                    }
                )
            security, auth_required = _security_info(document, operation, global_security, schemes)
            endpoints.append(
                {
                    "path": path[:500],
                    "method": method_name,
                    "operation_id": _text(operation.get("operationId"))[:180],
                    "summary": _text(operation.get("summary"))[:300],
                    "description": _text(operation.get("description")),
                    "tags": [str(tag) for tag in _as_list(operation.get("tags"))],
                    "parameters": parameters,
                    "security": security,
                    "auth_schemes": security,
                    "auth_required": auth_required,
                    "request_schema": body,
                    "response_schema": _response_summary(document, operation, spec_type),
                    "risk_level": _risk_level(path, method_name, auth_required, parameters, operation),
                    "deprecated": bool(operation.get("deprecated")),
                }
            )
    if len(endpoints) > MAX_ENDPOINTS:
        raise ValidationError(f"The specification declares too many endpoints (limit {MAX_ENDPOINTS}).")
    servers = []
    if spec_type == "openapi3":
        for raw_server in _as_list(document.get("servers")):
            server = _as_mapping(raw_server)
            if server.get("url"):
                servers.append(_text(server["url"]))
    else:
        host = _text(document.get("host"))
        if host:
            scheme = _text(_as_list(document.get("schemes"))[0]) if document.get("schemes") else "https"
            servers.append(f"{scheme}://{host}{_text(document.get('basePath'))}")
    tags = []
    for raw_tag in _as_list(document.get("tags")):
        name = _text(_as_mapping(raw_tag).get("name"))
        if name:
            tags.append(name)
    return {
        "spec_type": spec_type,
        "version": _text(document.get("openapi")) or _text(document.get("swagger")),
        "info": {
            "title": _text(info.get("title")),
            "version": _text(info.get("version")),
            "description": _text(info.get("description"))[:1000],
        },
        "servers": servers,
        "security_schemes": schemes,
        "security": global_security,
        "tags": tags,
        "endpoints": endpoints,
        "endpoint_count": len(endpoints),
    }


def read_spec_source(*, uploaded_file=None, content=None):
    if uploaded_file is not None:
        try:
            uploaded_file.seek(0)
        except (AttributeError, OSError, ValueError):
            pass
        raw = uploaded_file.read()
        if len(raw) > MAX_SPEC_BYTES:
            raise ValidationError("The specification file is too large.")
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValidationError("The specification must be UTF-8 encoded text.") from exc
        else:
            text = str(raw)
        try:
            uploaded_file.seek(0)
        except (AttributeError, OSError, ValueError):
            pass
        return text
    if content is None or not str(content).strip():
        raise ValidationError("Specification content is required.")
    return str(content)


def _sync_endpoints(*, project, specification, normalized):
    endpoint_count = 0
    parameter_count = 0
    for item in normalized["endpoints"]:
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
                "request_schema": item["request_schema"],
                "response_schema": item["response_schema"],
                "auth_required": item["auth_required"],
                "auth_schemes": item["auth_schemes"],
                "risk_level": item["risk_level"],
                "is_active": True,
            },
        )
        endpoint_count += 1
        for parameter in item["parameters"]:
            EndpointParameter.objects.update_or_create(
                endpoint=endpoint,
                name=parameter["name"],
                location=parameter["location"],
                defaults={
                    "required": parameter["required"],
                    "schema": parameter["schema"],
                    "example": parameter["example"],
                    "sensitive": parameter["sensitive"],
                },
            )
            parameter_count += 1
        stale = EndpointParameter.objects.filter(endpoint=endpoint)
        expected = [(parameter["name"], parameter["location"]) for parameter in item["parameters"]]
        for existing in stale:
            if (existing.name, existing.location) not in expected:
                existing.delete()
    return endpoint_count, parameter_count


@transaction.atomic
def import_openapi_spec(
    *,
    project,
    uploaded_file=None,
    content=None,
    name=None,
    source=None,
    source_url="",
    imported_by=None,
):
    if project is None or not getattr(project, "pk", None):
        raise ValidationError("A saved project is required.")
    text = read_spec_source(uploaded_file=uploaded_file, content=content)
    document = parse_spec_content(text, filename=_text(getattr(uploaded_file, "name", "")))
    normalized = normalize_spec(document)
    spec_source = source or (
        OpenApiSpecification.Source.FILE if uploaded_file is not None else OpenApiSpecification.Source.PASTED
    )
    info = _as_mapping(document.get("info"))
    specification = OpenApiSpecification.objects.create(
        project=project,
        name=(_text(name) or _text(info.get("title")) or "OpenAPI specification")[:180],
        version=(normalized["version"] or _text(info.get("version")))[:80],
        source=spec_source,
        source_url=_text(source_url)[:500],
        file=uploaded_file if spec_source == OpenApiSpecification.Source.FILE and uploaded_file is not None else None,
        raw_content=text,
        parsed_data=normalized,
        endpoint_count=normalized["endpoint_count"],
        imported_by=imported_by,
    )
    endpoint_count, parameter_count = _sync_endpoints(
        project=project,
        specification=specification,
        normalized=normalized,
    )
    specification.endpoint_count = endpoint_count
    specification.parsed_data = {**normalized, "parameter_count": parameter_count}
    specification.save(update_fields=["endpoint_count", "parsed_data"])
    return specification


@transaction.atomic
def discover_endpoints(*, project, specification=None, imported_by=None):
    if project is None or not getattr(project, "pk", None):
        raise ValidationError("A saved project is required.")
    specifications = OpenApiSpecification.objects.filter(project=project)
    if specification is not None:
        identifier = specification.pk if hasattr(specification, "pk") else specification
        specifications = specifications.filter(pk=identifier)
    specifications = list(specifications)
    if not specifications:
        raise ValidationError("No specifications are available for this project.")
    total_endpoints = 0
    total_parameters = 0
    for spec in specifications:
        filename = spec.file.name if spec.file else ""
        if spec.raw_content:
            text = spec.raw_content
        elif spec.file:
            try:
                spec.file.open("rb")
                raw = spec.file.read()
            finally:
                spec.file.close()
            if isinstance(raw, bytes):
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise ValidationError("The stored specification must be UTF-8 encoded text.") from exc
            else:
                text = str(raw)
        else:
            continue
        document = parse_spec_content(text, filename=filename)
        normalized = normalize_spec(document)
        endpoints, parameters = _sync_endpoints(project=project, specification=spec, normalized=normalized)
        spec.parsed_data = {**normalized, "parameter_count": parameters}
        spec.endpoint_count = endpoints
        spec.save(update_fields=["parsed_data", "endpoint_count"])
        total_endpoints += endpoints
        total_parameters += parameters
    return {
        "specifications": len(specifications),
        "endpoints": total_endpoints,
        "parameters": total_parameters,
    }


def get_endpoints_for_organization(organization):
    if organization is None:
        return ApiEndpoint.objects.none()
    return (
        ApiEndpoint.objects.filter(project__organization=organization)
        .select_related("project", "specification")
        .prefetch_related("endpoint_parameters")
    )


def get_endpoint_for_organization(endpoint_id, organization):
    if organization is None:
        return None
    try:
        return get_endpoints_for_organization(organization).filter(pk=endpoint_id).first()
    except (TypeError, ValueError):
        return None


def get_parameters_for_endpoint(endpoint):
    if endpoint is None:
        return EndpointParameter.objects.none()
    return endpoint.endpoint_parameters.all()


def risk_summary(*, organization):
    rows = get_endpoints_for_organization(organization).values("risk_level").annotate(total=Count("id"))
    return {row["risk_level"]: row["total"] for row in rows}
