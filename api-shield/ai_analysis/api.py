from django.urls import path
from rest_framework import generics, status
from rest_framework.response import Response

from accounts.permissions import HasOrganizationRole, IsOrganizationMember

from .models import AiAnalysis
from .serializers import AiAnalysisSerializer, AiAnalyzeSerializer
from .services import analyze_finding, analyze_scan


def scoped_queryset(queryset, request):
    organization = getattr(request, "current_organization", None)
    return queryset.filter(organization=organization) if organization else queryset.none()


class AiAnalysisListAPIView(generics.ListAPIView):
    serializer_class = AiAnalysisSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        queryset = scoped_queryset(
            AiAnalysis.objects.select_related("finding", "finding__scan_run").order_by("-created_at"),
            self.request,
        )
        priority = self.request.query_params.get("priority")
        source = self.request.query_params.get("source")
        if priority:
            queryset = queryset.filter(priority=priority)
        if source:
            queryset = queryset.filter(source=source)
        return queryset


class AiAnalysisDetailAPIView(generics.RetrieveAPIView):
    serializer_class = AiAnalysisSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get_queryset(self):
        return scoped_queryset(AiAnalysis.objects.select_related("finding", "finding__scan_run"), self.request)


class AiAnalyzeAPIView(generics.GenericAPIView):
    serializer_class = AiAnalyzeSerializer
    permission_classes = [IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        finding = serializer.validated_data.get("finding")
        scan_run = serializer.validated_data.get("scan_run")
        if finding is not None:
            analysis = analyze_finding(finding)
            payload = AiAnalysisSerializer(analysis, context={"request": request}).data
        else:
            summary = analyze_scan(scan_run)
            payload = {
                "scan_run_id": summary["scan_run_id"],
                "analyzed": summary["analyzed"],
                "analyses": AiAnalysisSerializer(summary["analyses"], many=True, context={"request": request}).data,
            }
        return Response(payload, status=status.HTTP_201_CREATED)


urlpatterns = [
    path("ai/", AiAnalysisListAPIView.as_view(), name="apishield-ai-list"),
    path("ai/analyze/", AiAnalyzeAPIView.as_view(), name="apishield-ai-analyze"),
    path("ai/<int:pk>/", AiAnalysisDetailAPIView.as_view(), name="apishield-ai-detail"),
]
