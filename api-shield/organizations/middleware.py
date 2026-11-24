from organizations.models import Organization


class OrganizationContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.current_organization = None
        request.current_role = None
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            organization_id = request.session.get("active_organization_id")
            organization = None
            if organization_id:
                organization = (
                    Organization.objects.filter(
                        id=organization_id,
                        is_active=True,
                        memberships__user=user,
                        memberships__is_active=True,
                    )
                    .distinct()
                    .first()
                )
            if organization is None:
                organization = (
                    Organization.objects.filter(
                        is_active=True,
                        memberships__user=user,
                        memberships__is_active=True,
                    )
                    .order_by("name")
                    .first()
                )
            if organization is not None:
                membership = organization.memberships.filter(user=user, is_active=True).first()
                request.current_organization = organization
                request.current_role = membership.role if membership else None
                request.session["active_organization_id"] = str(organization.id)
        return self.get_response(request)
