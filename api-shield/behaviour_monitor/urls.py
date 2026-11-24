from django.urls import path

from . import views

app_name = "behaviour_monitor"

urlpatterns = [
    path("logs/", views.RequestLogListView.as_view(), name="logs"),
    path("alerts/", views.BehaviourAlertListView.as_view(), name="alerts"),
    path("alerts/<int:pk>/", views.BehaviourAlertDetailView.as_view(), name="alert_detail"),
    path("alerts/<int:pk>/acknowledge/", views.AlertAcknowledgeView.as_view(), name="alert_acknowledge"),
    path("alerts/<int:pk>/resolve/", views.AlertResolveView.as_view(), name="alert_resolve"),
]
