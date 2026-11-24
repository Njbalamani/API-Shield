from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.AccountLoginView.as_view(), name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("api-keys/", views.ApiKeysView.as_view(), name="api_keys"),
    path("api-keys/create/", views.ApiKeyCreateView.as_view(), name="api_key_create"),
    path("api-keys/<int:pk>/revoke/", views.ApiKeyRevokeView.as_view(), name="api_key_revoke"),
]
