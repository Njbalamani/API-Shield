from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import ApiKey


class ApiKeyAuthentication(BaseAuthentication):
    keyword = b"ApiKey"

    def authenticate(self, request):
        header = request.headers.get("X-API-Key")
        if not header:
            return None
        key_hash = ApiKey.hash_key(header.strip())
        api_key = (
            ApiKey.objects.select_related("user", "organization")
            .filter(key_hash=key_hash, is_active=True, revoked_at__isnull=True, user__is_active=True)
            .first()
        )
        if api_key is None:
            raise AuthenticationFailed("Invalid API key.")
        if not api_key.organization.is_active:
            raise AuthenticationFailed("Organization is inactive.")
        from django.utils import timezone

        api_key.last_used_at = timezone.now()
        api_key.save(update_fields=["last_used_at"])
        request.current_organization = api_key.organization
        request.current_role = "api_key"
        return api_key.user, {"api_key": api_key}

    def authenticate_header(self, request):
        return 'ApiKey realm="api"'


class ApiKeyAuthenticationExtension(OpenApiAuthenticationExtension):
    target_class = "accounts.authentication.ApiKeyAuthentication"
    name = "ApiKeyAuth"

    def get_security_definition(self, auto_schema):
        return {"type": "apiKey", "in": "header", "name": "X-API-Key"}
