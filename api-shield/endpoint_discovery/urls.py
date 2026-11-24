from django.urls import path

from . import views

app_name = "endpoint_discovery"

urlpatterns = [
    path("", views.EndpointListView.as_view(), name="list"),
    path("<int:pk>/", views.EndpointDetailView.as_view(), name="detail"),
    path("discover/", views.EndpointDiscoverView.as_view(), name="discover"),
    path("<int:pk>/toggle/", views.EndpointToggleView.as_view(), name="toggle"),
]
