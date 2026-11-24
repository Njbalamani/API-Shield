from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.text import slugify

from accounts.models import User
from accounts.permissions import user_organizations

from .models import Organization, OrganizationMembership

VALID_ROLES = set(OrganizationMembership.Role.values)


def get_user_organizations(user):
    return user_organizations(user)


def get_organization_for_user(user, organization_id):
    try:
        return user_organizations(user).filter(pk=organization_id).first()
    except (TypeError, ValueError):
        return None


def switch_organization(*, user, organization_id):
    organization = get_organization_for_user(user, organization_id)
    if organization is None:
        raise PermissionDenied("You are not a member of that organization.")
    return organization


@transaction.atomic
def create_organization(*, name, slug, description, created_by):
    name = (name or "").strip()
    if not name:
        raise ValidationError({"name": "An organization name is required."})
    base_slug = slugify(slug or name)
    if not base_slug:
        raise ValidationError({"slug": "A valid slug is required."})
    candidate = base_slug
    suffix = 2
    while Organization.objects.filter(slug=candidate).exists():
        candidate = f"{base_slug}-{suffix}"
        suffix += 1
    return Organization.objects.create(
        name=name,
        slug=candidate[:200],
        description=(description or "").strip(),
        created_by=created_by,
    )


def list_members(*, organization):
    if organization is None:
        return OrganizationMembership.objects.none()
    return OrganizationMembership.objects.filter(organization=organization).select_related("user")


def get_membership(*, organization, membership_id):
    if organization is None:
        return None
    try:
        return OrganizationMembership.objects.filter(organization=organization, pk=membership_id).first()
    except (TypeError, ValueError):
        return None


@transaction.atomic
def add_member(*, organization, email, role):
    if role not in VALID_ROLES:
        raise ValidationError({"role": "Select a valid organization role."})
    email = (email or "").strip().lower()
    if not email:
        raise ValidationError({"email": "An email address is required."})
    user = User.objects.filter(email__iexact=email).first()
    if user is None:
        raise ValidationError({"email": "No account exists with this email address."})
    existing = OrganizationMembership.objects.filter(user=user, organization=organization).first()
    if existing is not None and existing.is_active:
        raise ValidationError({"email": "This user is already an active member."})
    if existing is not None:
        existing.role = role
        existing.is_active = True
        existing.save(update_fields=["role", "is_active"])
        return existing
    return OrganizationMembership.objects.create(
        user=user,
        organization=organization,
        role=role,
        is_active=True,
    )


@transaction.atomic
def remove_member(*, organization, membership_id):
    membership = get_membership(organization=organization, membership_id=membership_id)
    if membership is None:
        raise ValidationError("Membership not found.")
    membership.is_active = False
    membership.save(update_fields=["is_active"])
    cache.delete(f"apishield:org:{organization.pk}:members")
    return membership
