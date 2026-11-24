from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

api_patterns = [
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="api-schema"), name="docs"),
    path("redoc/", SpectacularRedocView.as_view(url_name="api-schema"), name="redoc"),
]

for module in (
    "accounts.api",
    "organizations.api",
    "api_projects.api",
    "endpoint_discovery.api",
    "api_scanner.api",
    "authentication_audit.api",
    "behaviour_monitor.api",
    "vulnerability_manager.api",
    "ai_analysis.api",
    "reports.api",
    "dashboard.api",
):
    api_patterns.append(path("", include(module)))

urlpatterns = api_patterns
