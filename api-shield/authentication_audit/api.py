from django.urls import path
from rest_framework import generics, status
from rest_framework.response import Response

from accounts.permissions import HasOrganizationRole, IsOrganizationMember

from .models import AuthenticationAudit
from .serializers import AuditRunSerializer, AuthenticationAuditSerializer
from .services import analyze_project


def scoped_queryset(queryset, request):
    organization = getattr(request, "current_organization", None)
    return queryset.filter(organization=organization) if organization else queryset.none()


def audit_queryset():
    return AuthenticationAudit.objects.select_related("project", "endpoint", "scan_run").prefetch_related("token_tests")


class AuthAuditListAPIView(generics.ListAPIView):
    serializer_class = AuthenticationAuditSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        queryset = scoped_queryset(audit_queryset(), self.request)
        result = self.request.query_params.get("result")
        auth_type = self.request.query_params.get("auth_type")
        if result:
            queryset = queryset.filter(result=result)
        if auth_type:
            queryset = queryset.filter(auth_type=auth_type)
        return queryset.order_by("-created_at")


class AuthAuditDetailAPIView(generics.RetrieveAPIView):
    serializer_class = AuthenticationAuditSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        return scoped_queryset(audit_queryset(), self.request)


class AuthAuditRunAPIView(generics.GenericAPIView):
    serializer_class = AuditRunSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        summary = analyze_project(
            serializer.validated_data["project"],
            user=request.user,
            scan_run=serializer.validated_data.get("scan_run"),
        )
        return Response(summary, status=status.HTTP_201_CREATED)


urlpatterns = [
    path("auth-audits/", AuthAuditListAPIView.as_view(), name="apishield-auth-audit-list"),
    path("auth-audits/run/", AuthAuditRunAPIView.as_view(), name="apishield-auth-audit-run"),
    path("auth-audits/<int:pk>/", AuthAuditDetailAPIView.as_view(), name="apishield-auth-audit-detail"),
]
