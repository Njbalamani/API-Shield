from django.contrib import admin

from accounts.permissions import user_organizations

from .models import Report


class OrganizationScopedAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        if request.user.is_superuser:
            return queryset
        return queryset.filter(organization__in=user_organizations(request.user))


@admin.register(Report)
class ReportAdmin(OrganizationScopedAdmin):
    list_display = ("created_at", "report_type", "file_format", "status", "project", "organization", "created_by")
    list_filter = ("report_type", "file_format", "status", "organization")
    search_fields = ("project__name", "organization__name", "error_message")
    raw_id_fields = ("organization", "project", "scan_run", "created_by")
    readonly_fields = ("created_at", "file", "error_message")
    date_hierarchy = "created_at"
