from django.contrib import admin

from .models import ApiEndpoint, EndpointParameter


@admin.register(ApiEndpoint)
class ApiEndpointAdmin(admin.ModelAdmin):
    list_display = ("method", "path", "project", "risk_level", "auth_required", "is_active")
    list_filter = ("method", "risk_level", "auth_required", "is_active")
    search_fields = ("path", "summary", "operation_id")
    readonly_fields = ("discovered_at", "updated_at")
    raw_id_fields = ("project", "specification")


@admin.register(EndpointParameter)
class EndpointParameterAdmin(admin.ModelAdmin):
    list_display = ("name", "location", "endpoint", "required", "sensitive")
    list_filter = ("location", "required", "sensitive")
    search_fields = ("name", "endpoint__path")
    raw_id_fields = ("endpoint",)
