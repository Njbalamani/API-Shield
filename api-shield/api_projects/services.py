from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.utils.text import slugify

from .models import ApiProject, OpenApiSpecification, ScanPolicy

VALID_ENVIRONMENTS = set(ApiProject.Environment.values)


def normalize_base_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValidationError({"base_url": "Enter a valid HTTP or HTTPS URL."}) from exc
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValidationError({"base_url": "Enter a valid HTTP or HTTPS URL."})
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValidationError({"base_url": "The base URL must not contain credentials, a query string, or a fragment."})
    return value


def validate_project_data(data, *, organization, instance=None):
    errors = {}
    name = (data.get("name") or "").strip()
    if not name:
        errors["name"] = "A project name is required."
    environment = data.get("environment") or ApiProject.Environment.CONTROLLED_LAB
    if environment not in VALID_ENVIRONMENTS:
        errors["environment"] = "Select a valid environment."
    try:
        base_url = normalize_base_url(data.get("base_url"))
    except ValidationError as exc:
        errors.update(exc.message_dict)
        base_url = ""
    authorization_confirmed = bool(data.get("authorization_confirmed"))
    authorization_reference = (data.get("authorization_reference") or "").strip()
    if (base_url or environment == ApiProject.Environment.PRODUCTION) and not authorization_confirmed:
        errors["authorization_confirmed"] = "Confirm that you are authorized to test this target."
    if authorization_confirmed and not authorization_reference:
        errors["authorization_reference"] = "Provide an authorization reference."
    slug = (data.get("slug") or "").strip() or slugify(name)
    if not slug:
        errors["slug"] = "A valid slug is required."
    elif (
        ApiProject.objects.filter(organization=organization, slug=slug)
        .exclude(pk=instance.pk if instance else None)
        .exists()
    ):
        errors["slug"] = "A project with this slug already exists in the organization."
    if errors:
        raise ValidationError(errors)
    return {
        "name": name,
        "slug": slug[:200],
        "description": (data.get("description") or "").strip(),
        "environment": environment,
        "base_url": base_url,
        "authorization_confirmed": authorization_confirmed,
        "authorization_reference": authorization_reference,
    }


def _policy_defaults(project):
    config = getattr(settings, "APISHIELD", {})
    host = ""
    if project.authorization_confirmed and project.base_url:
        try:
            host = urlparse(project.base_url).hostname or ""
        except ValueError:
            host = ""
    return {
        "allow_passive_tests": True,
        "allow_active_tests": False,
        "allow_zap": False,
        "max_requests": int(config.get("MAX_ACTIVE_REQUESTS", 40)),
        "rate_limit_rpm": int(config.get("SCAN_RATE_LIMIT_RPM", 30)),
        "timeout_seconds": int(config.get("SCAN_TIMEOUT_SECONDS", 15)),
        "allowed_hosts": host,
    }


@transaction.atomic
def create_project(
    *,
    organization,
    owner,
    name,
    slug=None,
    description="",
    environment=ApiProject.Environment.CONTROLLED_LAB,
    base_url="",
    authorization_confirmed=False,
    authorization_reference="",
):
    cleaned = validate_project_data(
        {
            "name": name,
            "slug": slug,
            "description": description,
            "environment": environment,
            "base_url": base_url,
            "authorization_confirmed": authorization_confirmed,
            "authorization_reference": authorization_reference,
        },
        organization=organization,
    )
    project = ApiProject.objects.create(organization=organization, owner=owner, **cleaned)
    ScanPolicy.objects.create(project=project, **_policy_defaults(project))
    return project


@transaction.atomic
def update_project(*, project, data):
    cleaned = validate_project_data(data, organization=project.organization, instance=project)
    for field, value in cleaned.items():
        setattr(project, field, value)
    project.save(update_fields=[*cleaned.keys(), "updated_at"])
    policy = ScanPolicy.objects.filter(project=project).first()
    if policy is not None and not project.authorization_confirmed:
        policy.allowed_hosts = ""
        policy.allow_active_tests = False
        policy.allow_zap = False
        policy.save(update_fields=["allowed_hosts", "allow_active_tests", "allow_zap"])
    return project


@transaction.atomic
def confirm_authorization(*, project, reference):
    reference = (reference or "").strip()
    if not reference:
        raise ValidationError({"authorization_reference": "Provide an authorization reference."})
    project.authorization_confirmed = True
    project.authorization_reference = reference[:200]
    project.save(update_fields=["authorization_confirmed", "authorization_reference", "updated_at"])
    policy = ScanPolicy.objects.filter(project=project).first()
    if policy is not None and project.base_url:
        policy.allowed_hosts = urlparse(project.base_url).hostname or ""
        policy.save(update_fields=["allowed_hosts"])
    return project


def get_projects_for_organization(organization, search=""):
    if organization is None:
        return ApiProject.objects.none()
    queryset = ApiProject.objects.filter(organization=organization).annotate(
        endpoint_count=Count("endpoints", distinct=True)
    )
    term = (search or "").strip()
    if term:
        queryset = queryset.filter(Q(name__icontains=term) | Q(slug__icontains=term) | Q(description__icontains=term))
    return queryset.select_related("organization", "owner")


def get_project_for_organization(project_id, organization):
    if organization is None or project_id in (None, ""):
        return None
    try:
        return ApiProject.objects.filter(pk=project_id, organization=organization).first()
    except (TypeError, ValueError):
        return None


def get_specifications_for_project(project):
    if project is None:
        return OpenApiSpecification.objects.none()
    return OpenApiSpecification.objects.filter(project=project).select_related("imported_by")
