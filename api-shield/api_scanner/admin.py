from django.contrib import admin

from .models import ScanFinding, ScanLog, ScanRule, ScanRun


class OrganizationScopedAdmin(admin.ModelAdmin):
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "organization":
            from accounts.permissions import user_organizations

            kwargs["queryset"] = user_organizations(request.user)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(ScanRule)
class ScanRuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "title", "category", "severity", "engine", "enabled")
    list_filter = ("severity", "engine", "enabled", "category")
    search_fields = ("rule_id", "title", "description", "owasp_category", "cwe")
    readonly_fields = ("created_at", "updated_at")


@admin.register(ScanRun)
class ScanRunAdmin(OrganizationScopedAdmin):
    list_display = (
        "id",
        "project",
        "organization",
        "status",
        "mode",
        "findings_count",
        "critical_count",
        "high_count",
        "risk_score",
        "started_at",
    )
    list_filter = ("status", "mode", "organization")
    search_fields = ("project__name", "organization__name", "error_message")
    readonly_fields = ("started_at", "finished_at", "updated_at", "summary")


@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
    list_display = ("title", "scan_run", "severity", "confidence", "status", "verified", "risk_score")
    list_filter = ("severity", "confidence", "status", "verified", "owasp_category")
    search_fields = ("title", "description", "cwe", "owasp_category")
    readonly_fields = ("created_at", "updated_at")

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "scan_run":
            from accounts.permissions import user_organizations

            kwargs["queryset"] = ScanRun.objects.filter(organization__in=user_organizations(request.user))
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ("scan_run", "level", "message", "created_at")
    list_filter = ("level",)
    search_fields = ("message", "scan_run__project__name")
    readonly_fields = ("created_at",)
