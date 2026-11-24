from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("", views.ReportListView.as_view(), name="list"),
    path("generate/", views.ReportGenerateView.as_view(), name="generate"),
    path("<int:pk>/download/", views.ReportDownloadView.as_view(), name="download"),
]
