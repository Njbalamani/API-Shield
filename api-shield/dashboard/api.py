from django.urls import path
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsOrganizationMember
from api_projects.models import ApiProject

from .serializers import MetricsSerializer, TopologySerializer
from .services import get_metrics, get_topology


def _organization(request):
    return getattr(request, "current_organization", None)


def _options(request):
    organization = _organization(request)
    try:
        days = int(request.query_params.get("days", 7))
    except (TypeError, ValueError):
        days = 7
    days = max(1, min(days, 365))
    project = None
    project_id = request.query_params.get("project")
    if organization is not None and project_id and str(project_id).isdigit():
        project = ApiProject.objects.filter(id=int(project_id), organization=organization).first()
    include_inactive = request.query_params.get("include_inactive") in {"1", "true", "True"}
    return organization, days, project, include_inactive


@extend_schema(responses=MetricsSerializer)
class DashboardMetricsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get(self, request):
        organization, days, _, _ = _options(request)
        if organization is None:
            return Response({"detail": "No active organization."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(MetricsSerializer(get_metrics(organization, days)).data)


@extend_schema(responses=TopologySerializer)
class DashboardTopologyAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get(self, request):
        organization, _, project, include_inactive = _options(request)
        if organization is None:
            return Response({"detail": "No active organization."}, status=status.HTTP_400_BAD_REQUEST)
        topology = get_topology(organization, include_inactive=include_inactive, project=project)
        return Response(TopologySerializer(topology).data)


@extend_schema(
    responses=inline_serializer(
        name="DashboardSummary",
        fields={
            "metrics": MetricsSerializer(),
            "topology": TopologySerializer(),
        },
    )
)
class DashboardSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "viewer"

    def get(self, request):
        organization, days, project, include_inactive = _options(request)
        if organization is None:
            return Response({"detail": "No active organization."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "metrics": MetricsSerializer(get_metrics(organization, days)).data,
                "topology": TopologySerializer(
                    get_topology(organization, include_inactive=include_inactive, project=project)
                ).data,
            }
        )


urlpatterns = [
    path("dashboard/metrics/", DashboardMetricsAPIView.as_view(), name="apishield-dashboard-metrics"),
    path("dashboard/topology/", DashboardTopologyAPIView.as_view(), name="apishield-dashboard-topology"),
    path("dashboard/summary/", DashboardSummaryAPIView.as_view(), name="apishield-dashboard-summary"),
]
