from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("organizations/", include("organizations.urls")),
    path("projects/", include("api_projects.urls")),
    path("endpoints/", include("endpoint_discovery.urls")),
    path("scans/", include("api_scanner.urls")),
    path("auth-audits/", include("authentication_audit.urls")),
    path("monitor/", include("behaviour_monitor.urls")),
    path("vulnerabilities/", include("vulnerability_manager.urls")),
    path("ai/", include("ai_analysis.urls")),
    path("reports/", include("reports.urls")),
    path("dashboard/", include("dashboard.urls")),
    path("api/", include("config.api")),
    path("oauth/", include("oauth2_provider.urls", namespace="oauth2_provider")),
]
