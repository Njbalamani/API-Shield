from django.urls import path

from . import views

app_name = "api_projects"

urlpatterns = [
    path("", views.ProjectListView.as_view(), name="list"),
    path("create/", views.ProjectCreateView.as_view(), name="create"),
    path("<int:pk>/", views.ProjectDetailView.as_view(), name="detail"),
    path("<int:pk>/update/", views.ProjectUpdateView.as_view(), name="update"),
    path("<int:pk>/delete/", views.ProjectDeleteView.as_view(), name="delete"),
    path("<int:pk>/spec-upload/", views.ProjectSpecUploadView.as_view(), name="spec_upload"),
    path("<int:pk>/authorize/", views.ProjectAuthorizationView.as_view(), name="authorize"),
]
