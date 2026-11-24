from django.urls import path
from rest_framework import generics, status
from rest_framework.response import Response

from accounts.permissions import HasOrganizationRole, IsOrganizationMember

from .models import ScanFinding, ScanLog, ScanRule, ScanRun
from .serializers import (
    ScanFindingSerializer,
    ScanFindingStatusSerializer,
    ScanLogSerializer,
    ScanRuleSerializer,
    ScanRunSerializer,
    ScanStartSerializer,
)
from .services import create_scan, run_scan


def scoped_queryset(queryset, request, field="organization"):
    organization = getattr(request, "current_organization", None)
    return queryset.filter(**{field: organization}) if organization else queryset.none()


class ScanListAPIView(generics.ListAPIView):
    serializer_class = ScanRunSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        queryset = scoped_queryset(ScanRun.objects.select_related("project", "initiated_by"), self.request)
        status_filter = self.request.query_params.get("status")
        mode_filter = self.request.query_params.get("mode")
        project_filter = self.request.query_params.get("project")
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if mode_filter:
            queryset = queryset.filter(mode=mode_filter)
        if project_filter:
            queryset = queryset.filter(project_id=project_filter)
        return queryset.order_by("-started_at")


class ScanDetailAPIView(generics.RetrieveAPIView):
    serializer_class = ScanRunSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        return scoped_queryset(ScanRun.objects.select_related("project", "initiated_by"), self.request)


class ScanLogsAPIView(generics.ListAPIView):
    serializer_class = ScanLogSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        return scoped_queryset(
            ScanLog.objects.filter(scan_run_id=self.kwargs["pk"]), self.request, "scan_run__organization"
        ).order_by("created_at")


class ScanStartAPIView(generics.GenericAPIView):
    serializer_class = ScanStartSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        scan_run = create_scan(
            project=serializer.validated_data["project"],
            user=request.user,
            mode=serializer.validated_data["mode"],
            specification=serializer.validated_data.get("specification"),
        )
        run_scan(scan_run)
        return Response(ScanRunSerializer(scan_run, context={"request": request}).data, status=status.HTTP_201_CREATED)


class ScanFindingListAPIView(generics.ListAPIView):
    serializer_class = ScanFindingSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        queryset = scoped_queryset(
            ScanFinding.objects.select_related("scan_run", "endpoint", "rule"),
            self.request,
            "scan_run__organization",
        )
        scan_filter = self.request.query_params.get("scan_run")
        severity_filter = self.request.query_params.get("severity")
        if scan_filter:
            queryset = queryset.filter(scan_run_id=scan_filter)
        if severity_filter:
            queryset = queryset.filter(severity=severity_filter)
        return queryset.order_by("-risk_score", "-created_at")


class ScanFindingDetailAPIView(generics.RetrieveUpdateAPIView):
    serializer_class = ScanFindingSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self):
        return scoped_queryset(
            ScanFinding.objects.select_related("scan_run", "endpoint", "rule"),
            self.request,
            "scan_run__organization",
        )

    def get_serializer_class(self):
        if self.request.method in {"PATCH", "PUT"}:
            return ScanFindingStatusSerializer
        return ScanFindingSerializer


class ScanRuleListAPIView(generics.ListAPIView):
    serializer_class = ScanRuleSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        return ScanRule.objects.filter(enabled=True).order_by("category", "rule_id")


urlpatterns = [
    path("scans/", ScanListAPIView.as_view(), name="apishield-scan-list"),
    path("scans/start/", ScanStartAPIView.as_view(), name="apishield-scan-start"),
    path("scans/<int:pk>/", ScanDetailAPIView.as_view(), name="apishield-scan-detail"),
    path("scans/<int:pk>/logs/", ScanLogsAPIView.as_view(), name="apishield-scan-logs"),
    path("findings/", ScanFindingListAPIView.as_view(), name="apishield-scan-finding-list"),
    path("findings/<int:pk>/", ScanFindingDetailAPIView.as_view(), name="apishield-scan-finding-detail"),
    path("rules/", ScanRuleListAPIView.as_view(), name="apishield-scan-rule-list"),
]
