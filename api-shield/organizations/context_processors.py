from accounts.permissions import has_minimum_role, user_organizations


def apishield_context(request):
    organizations = []
    if request.user.is_authenticated:
        organizations = list(user_organizations(request.user))
    organization = getattr(request, "current_organization", None)
    role = getattr(request, "current_role", None)
    return {
        "apishield_organizations": organizations,
        "current_organization": organization,
        "current_role": role,
        "can_manage": has_minimum_role(request.user, organization, "admin"),
        "can_scan": has_minimum_role(request.user, organization, "analyst"),
        "can_fix": has_minimum_role(request.user, organization, "developer"),
    }
