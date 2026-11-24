from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

ROLE_RANK = {
    "viewer": 1,
    "developer": 2,
    "analyst": 3,
    "admin": 4,
}


def has_minimum_role(user, organization, required_role="viewer"):
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    if organization is None:
        return False
    membership = organization.memberships.filter(user=user, is_active=True).first()
    if membership is None:
        return False
    return ROLE_RANK.get(membership.role, 0) >= ROLE_RANK.get(required_role, 1)


def user_organizations(user):
    from organizations.models import Organization

    if not user or not user.is_authenticated:
        return Organization.objects.none()
    if user.is_superuser:
        return Organization.objects.filter(is_active=True)
    return Organization.objects.filter(is_active=True, memberships__user=user, memberships__is_active=True).distinct()


class OrganizationRoleRequiredMixin(AccessMixin):
    required_role = "viewer"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        organization = getattr(request, "current_organization", None)
        if not has_minimum_role(request.user, organization, self.required_role):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class IsOrganizationMember(BasePermission):
    def has_permission(self, request, view):
        return bool(getattr(request, "current_organization", None))


class HasOrganizationRole(BasePermission):
    required_role = "viewer"

    def has_permission(self, request, view):
        return has_minimum_role(
            request.user,
            getattr(request, "current_organization", None),
            getattr(view, "required_role", self.required_role),
        )


class IsAdminRole(HasOrganizationRole):
    required_role = "admin"


class IsAnalystRole(HasOrganizationRole):
    required_role = "analyst"


class IsDeveloperRole(HasOrganizationRole):
    required_role = "developer"
