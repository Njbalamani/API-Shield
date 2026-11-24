from django.contrib import admin

from .models import AuthenticationAudit, TokenTest


@admin.register(AuthenticationAudit)
class AuthenticationAuditAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "project",
        "endpoint",
        "auth_type",
        "result",
        "expiration_detected",
        "insecure_token_handling",
        "authorization_controls",
        "score",
        "created_at",
    )
    list_filter = ("auth_type", "result", "organization", "expiration_detected", "insecure_token_handling")
    search_fields = ("project__name", "endpoint__path", "auth_type")
    readonly_fields = ("created_at",)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "organization":
            from accounts.permissions import user_organizations

            kwargs["queryset"] = user_organizations(request.user)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(TokenTest)
class TokenTestAdmin(admin.ModelAdmin):
    list_display = ("name", "audit", "outcome", "created_at")
    list_filter = ("outcome",)
    search_fields = ("name", "audit__project__name")
    readonly_fields = ("created_at",)
