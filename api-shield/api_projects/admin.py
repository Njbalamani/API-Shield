from django.contrib import admin

from .models import ApiProject, OpenApiSpecification, ScanPolicy


@admin.register(ApiProject)
class ApiProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "organization", "environment", "status", "authorization_confirmed", "owner")
    list_filter = ("environment", "status", "authorization_confirmed", "organization")
    search_fields = ("name", "slug", "description", "base_url")
    readonly_fields = ("created_at", "updated_at")
    raw_id_fields = ("organization", "owner")


@admin.register(OpenApiSpecification)
class OpenApiSpecificationAdmin(admin.ModelAdmin):
    list_display = ("name", "project", "version", "source", "endpoint_count", "imported_by", "imported_at")
    list_filter = ("source",)
    search_fields = ("name", "version", "source_url")
    readonly_fields = ("parsed_data", "endpoint_count", "imported_at")
    raw_id_fields = ("project", "imported_by")


@admin.register(ScanPolicy)
class ScanPolicyAdmin(admin.ModelAdmin):
    list_display = ("project", "allow_passive_tests", "allow_active_tests", "allow_zap", "max_requests")
    list_filter = ("allow_passive_tests", "allow_active_tests", "allow_zap")
    search_fields = ("project__name",)
    raw_id_fields = ("project",)
