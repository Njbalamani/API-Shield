from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import ApiKey, LoginAttempt, User


@admin.register(User)
class APIShieldUserAdmin(UserAdmin):
    list_display = ("email", "username", "full_name", "role", "is_staff", "is_active")
    list_filter = ("role", "is_staff", "is_active", "mfa_enabled")
    search_fields = ("email", "username", "full_name")
    ordering = ("email",)
    fieldsets = UserAdmin.fieldsets + (("APIShield", {"fields": ("full_name", "role", "mfa_enabled")}),)
    add_fieldsets = UserAdmin.add_fieldsets + (("APIShield", {"fields": ("email", "full_name", "role")}),)


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("email", "ip_address", "success", "created_at")
    list_filter = ("success",)
    search_fields = ("email", "ip_address")
    readonly_fields = ("email", "ip_address", "success", "created_at")
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "prefix", "user", "organization", "is_active", "last_used_at", "revoked_at")
    list_filter = ("is_active", "organization")
    search_fields = ("name", "prefix", "user__email")
    readonly_fields = ("prefix", "key_hash", "last_used_at", "revoked_at", "created_at")
    raw_id_fields = ("user", "organization")
    actions = ("revoke_selected",)

    @admin.action(description="Revoke selected API keys")
    def revoke_selected(self, request, queryset):
        from .services import revoke_api_key

        for api_key in queryset.filter(is_active=True):
            revoke_api_key(api_key=api_key, user=request.user)
