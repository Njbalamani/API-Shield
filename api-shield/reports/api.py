from django.http import FileResponse
from django.urls import path
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsOrganizationMember

from .models import Report
from .serializers import ReportGenerateSerializer, ReportSerializer, ReportTypesSerializer
from .services import create_report, report_download


def _organization(request):
    return getattr(request, "current_organization", None)


class ReportListAPIView(generics.ListAPIView):
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get_queryset(self):
        organization = _organization(self.request)
        if organization is None:
            return Report.objects.none()
        queryset = Report.objects.filter(organization=organization).select_related("project", "scan_run", "created_by")
        params = self.request.query_params
        for field in ("report_type", "file_format", "status"):
            if params.get(field):
                queryset = queryset.filter(**{field: params[field]})
        if params.get("project"):
            queryset = queryset.filter(project_id=params["project"])
        return queryset.order_by("-created_at")


class ReportDetailAPIView(generics.RetrieveAPIView):
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get_queryset(self):
        organization = _organization(self.request)
        if organization is None:
            return Report.objects.none()
        return Report.objects.filter(organization=organization).select_related("project", "scan_run", "created_by")


@extend_schema(request=ReportGenerateSerializer, responses={status.HTTP_201_CREATED: ReportSerializer})
class ReportGenerateAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def post(self, request):
        organization = _organization(request)
        if organization is None:
            return Response({"detail": "No active organization."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ReportGenerateSerializer(data=request.data, context={"organization": organization})
        serializer.is_valid(raise_exception=True)
        report = create_report(
            organization,
            serializer.validated_data["project"],
            created_by=request.user,
            report_type=serializer.validated_data["report_type"],
            file_format=serializer.validated_data["file_format"],
            scan_run=serializer.validated_data.get("scan_run"),
            parameters=serializer.validated_data.get("parameters", {}),
        )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)


@extend_schema(responses={status.HTTP_200_OK: OpenApiTypes.BINARY})
class ReportDownloadAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get(self, request, pk):
        organization = _organization(request)
        report = Report.objects.filter(pk=pk, organization=organization).first() if organization else None
        if report is None:
            return Response({"detail": "Report not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            file_object, filename, content_type = report_download(report)
        except (FileNotFoundError, ValueError):
            return Response({"detail": "Report file is not available."}, status=status.HTTP_404_NOT_FOUND)
        return FileResponse(file_object, as_attachment=True, filename=filename, content_type=content_type)


@extend_schema(responses=ReportTypesSerializer)
class ReportTypesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get(self, request):
        return Response(
            {
                "report_types": [{"value": value, "label": label} for value, label in Report.ReportType.choices],
                "file_formats": [{"value": value, "label": label} for value, label in Report.FileFormat.choices],
            }
        )


urlpatterns = [
    path("reports/", ReportListAPIView.as_view(), name="apishield-report-list"),
    path("reports/generate/", ReportGenerateAPIView.as_view(), name="apishield-report-generate"),
    path("reports/types/", ReportTypesAPIView.as_view(), name="apishield-report-types"),
    path("reports/<int:pk>/", ReportDetailAPIView.as_view(), name="apishield-report-detail"),
    path("reports/<int:pk>/download/", ReportDownloadAPIView.as_view(), name="apishield-report-download"),
]
