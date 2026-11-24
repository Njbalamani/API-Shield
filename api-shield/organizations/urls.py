from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("", views.OrganizationListView.as_view(), name="list"),
    path("<int:pk>/", views.OrganizationDetailView.as_view(), name="detail"),
    path("switch/", views.OrganizationSwitchView.as_view(), name="switch"),
    path("members/", views.OrganizationMembersView.as_view(), name="members"),
    path("members/add/", views.OrganizationMemberAddView.as_view(), name="member_add"),
    path("members/<int:pk>/remove/", views.OrganizationRemoveMemberView.as_view(), name="member_remove"),
]
