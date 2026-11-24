from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.DashboardIndexView.as_view(), name="index"),
    path("metrics.json", views.DashboardMetricsJsonView.as_view(), name="metrics"),
    path("topology.json", views.DashboardTopologyJsonView.as_view(), name="topology"),
]
