from django.contrib import admin

from accounts.permissions import user_organizations

from .models import ApiRequestLog, BehaviourAlert


class OrganizationScopedAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        if request.user.is_superuser:
            return queryset
        return queryset.filter(organization__in=user_organizations(request.user))


@admin.register(ApiRequestLog)
class ApiRequestLogAdmin(OrganizationScopedAdmin):
    list_display = ("timestamp", "method", "path", "project", "status_code", "response_time_ms", "is_suspicious")
    list_filter = ("method", "is_suspicious", "status_code", "project")
    search_fields = ("path", "ip_address", "project__name")
    readonly_fields = ("timestamp", "query_keys")
    raw_id_fields = ("organization", "project", "endpoint")
    date_hierarchy = "timestamp"


@admin.register(BehaviourAlert)
class BehaviourAlertAdmin(OrganizationScopedAdmin):
    list_display = ("created_at", "title", "alert_type", "severity", "status", "project")
    list_filter = ("alert_type", "severity", "status", "project")
    search_fields = ("title", "description", "project__name")
    readonly_fields = ("created_at", "updated_at", "evidence")
    raw_id_fields = ("organization", "project", "endpoint")
    date_hierarchy = "created_at"
