import hashlib
import ipaddress
import logging

from django.contrib.auth import authenticate
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from accounts.permissions import has_minimum_role, user_organizations
from organizations.models import Organization, OrganizationMembership

from .models import ApiKey, LoginAttempt, User

logger = logging.getLogger("apishield")

LOGIN_FAILURE_LIMIT = 5
LOGIN_LOCK_SECONDS = 15 * 60


def normalize_email(email):
    return (email or "").strip().lower()


def client_ip(request):
    address = (getattr(request, "META", {}) or {}).get("REMOTE_ADDR") or ""
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


def _login_key(email, ip_address, suffix):
    digest = hashlib.sha256(f"{normalize_email(email)}|{ip_address or ''}".encode()).hexdigest()
    return f"apishield:login:{suffix}:{digest}"


def is_login_locked(email, ip_address=None):
    return bool(cache.get(_login_key(email, ip_address, "locked"), False))


def failed_login_count(email, ip_address=None):
    return int(cache.get(_login_key(email, ip_address, "failures"), 0) or 0)


def remaining_login_attempts(email, ip_address=None):
    return max(0, LOGIN_FAILURE_LIMIT - failed_login_count(email, ip_address))


def record_failed_login(email, ip_address=None):
    count = failed_login_count(email, ip_address) + 1
    cache.set(_login_key(email, ip_address, "failures"), count, LOGIN_LOCK_SECONDS)
    if count >= LOGIN_FAILURE_LIMIT:
        cache.set(_login_key(email, ip_address, "locked"), True, LOGIN_LOCK_SECONDS)
        cache.delete(_login_key(email, ip_address, "failures"))
    return count


def clear_login_failures(email, ip_address=None):
    cache.delete_many([_login_key(email, ip_address, "failures"), _login_key(email, ip_address, "locked")])


def login_user(*, request, email, password):
    email = normalize_email(email)
    ip_address = client_ip(request)
    if is_login_locked(email, ip_address):
        LoginAttempt.objects.create(email=email, ip_address=ip_address, success=False)
        return None, "locked"
    user = authenticate(request=request, username=email, password=password)
    if user is not None and user.is_active:
        clear_login_failures(email, ip_address)
        LoginAttempt.objects.create(email=email, ip_address=ip_address, success=True)
        return user, None
    count = record_failed_login(email, ip_address)
    LoginAttempt.objects.create(email=email, ip_address=ip_address, success=False)
    logger.info("Rejected login attempt for an account from %s (failure %s)", ip_address, count)
    return None, "locked" if is_login_locked(email, ip_address) else "invalid"


@transaction.atomic
def register_user(*, email, username, full_name, password, organization_name, organization_slug=None):
    email = normalize_email(email)
    username = (username or "").strip()
    full_name = (full_name or "").strip()
    organization_name = (organization_name or "").strip()
    if not email or not username or not full_name or not organization_name:
        raise ValidationError("Email, username, full name, and organization name are required.")
    if User.objects.filter(email__iexact=email).exists():
        raise ValidationError({"email": "An account with this email already exists."})
    if User.objects.filter(username__iexact=username).exists():
        raise ValidationError({"username": "This username is already taken."})
    user = User(email=email, username=username, full_name=full_name, role=User.Role.ADMIN)
    user.set_password(password)
    user.full_clean()
    user.save()
    base_slug = slugify(organization_slug or organization_name) or f"organization-{user.pk}"
    slug = base_slug
    suffix = 2
    while Organization.objects.filter(slug=slug).exists():
        slug = f"{base_slug}-{suffix}"
        suffix += 1
    organization = Organization.objects.create(name=organization_name, slug=slug, created_by=user)
    OrganizationMembership.objects.create(
        user=user,
        organization=organization,
        role=OrganizationMembership.Role.ADMIN,
        is_active=True,
    )
    return user, organization


@transaction.atomic
def update_profile(*, user, email, username, full_name):
    email = normalize_email(email)
    username = (username or "").strip()
    full_name = (full_name or "").strip()
    if User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        raise ValidationError({"email": "An account with this email already exists."})
    if User.objects.filter(username__iexact=username).exclude(pk=user.pk).exists():
        raise ValidationError({"username": "This username is already taken."})
    user.email = email
    user.username = username
    user.full_name = full_name
    user.full_clean()
    user.save(update_fields=["email", "username", "full_name", "updated_at"])
    return user


def list_api_keys(*, user, organization):
    if organization is None:
        return ApiKey.objects.none()
    return ApiKey.objects.filter(user=user, organization=organization).select_related("organization")


def get_api_key(*, user, organization, key_id):
    if organization is None:
        return None
    try:
        return ApiKey.objects.filter(user=user, organization=organization, pk=key_id).first()
    except (TypeError, ValueError):
        return None


def create_api_key(*, user, organization, name):
    if organization is None or not has_minimum_role(user, organization, "developer"):
        raise PermissionDenied("You cannot create API keys for this organization.")
    name = (name or "").strip()
    if not name:
        raise ValidationError({"name": "A key name is required."})
    return ApiKey.create_key(name=name, user=user, organization=organization)


def revoke_api_key(*, api_key, user):
    if api_key.user_id != user.pk and not user.is_superuser:
        raise PermissionDenied("You cannot revoke this API key.")
    api_key.is_active = False
    api_key.revoked_at = timezone.now()
    api_key.save(update_fields=["is_active", "revoked_at"])
    return api_key


def resolve_request_organization(request):
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return None
    organizations = user_organizations(user)
    query = getattr(request, "query_params", None)
    if query is None:
        query = getattr(request, "GET", {})
    requested_id = request.headers.get("X-Organization-ID") or query.get("organization")
    if requested_id:
        try:
            organization = organizations.filter(pk=requested_id).first()
        except (TypeError, ValueError):
            organization = None
        if organization is None:
            raise PermissionDenied("You are not a member of that organization.")
        request.current_organization = organization
        return organization
    organization = getattr(request, "current_organization", None)
    if organization is not None:
        if not has_minimum_role(user, organization, "viewer"):
            raise PermissionDenied("You are not a member of the active organization.")
        return organization
    organization = organizations.first()
    if organization is not None:
        request.current_organization = organization
    return organization
