from django.urls import path

from . import views

app_name = "authentication_audit"

urlpatterns = [
    path("", views.AuthAuditListView.as_view(), name="list"),
    path("run/", views.AuthAuditRunView.as_view(), name="run"),
    path("<int:pk>/", views.AuthAuditDetailView.as_view(), name="detail"),
]
