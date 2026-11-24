from django.urls import path

from . import views

app_name = "api_scanner"

urlpatterns = [
    path("", views.ScanListView.as_view(), name="list"),
    path("start/", views.ScanStartView.as_view(), name="start"),
    path("<int:pk>/", views.ScanDetailView.as_view(), name="detail"),
    path("findings/", views.ScanFindingListView.as_view(), name="finding_list"),
    path("findings/<int:pk>/", views.ScanFindingDetailView.as_view(), name="finding_detail"),
]
