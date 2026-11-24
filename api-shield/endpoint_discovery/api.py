from django.core.exceptions import ValidationError
from django.urls import include, path
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, status, viewsets
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsAnalystRole, IsOrganizationMember
from accounts.services import resolve_request_organization
from api_projects import services as project_services
from api_projects.models import OpenApiSpecification

from . import services
from .models import EndpointParameter
from .serializers import ApiEndpointSerializer, DiscoverSerializer, EndpointParameterSerializer


class OrganizationContextMixin:
    def initial(self, request, *args, **kwargs):
        resolve_request_organization(request)
        return super().initial(request, *args, **kwargs)


class ApiEndpointViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ApiEndpointSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    filter_backends = [OrderingFilter]
    ordering_fields = ("path", "method", "risk_level", "discovered_at")

    def get_queryset(self):
        queryset = services.get_endpoints_for_organization(getattr(self.request, "current_organization", None))
        params = self.request.query_params
        if params.get("project"):
            queryset = queryset.filter(project_id=params["project"])
        if params.get("method"):
            queryset = queryset.filter(method=params["method"].upper())
        if params.get("risk_level"):
            queryset = queryset.filter(risk_level=params["risk_level"])
        if params.get("auth_required") in {"true", "1", "yes"}:
            queryset = queryset.filter(auth_required=True)
        elif params.get("auth_required") in {"false", "0", "no"}:
            queryset = queryset.filter(auth_required=False)
        return queryset


class EndpointParameterViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = EndpointParameterSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]

    def get_queryset(self):
        queryset = EndpointParameter.objects.filter(
            endpoint__project__organization=getattr(self.request, "current_organization", None)
        ).select_related("endpoint")
        endpoint_id = self.request.query_params.get("endpoint")
        if endpoint_id:
            queryset = queryset.filter(endpoint_id=endpoint_id)
        return queryset


@extend_schema(
    request=DiscoverSerializer,
    responses=inline_serializer(
        name="DiscoverySummary",
        fields={
            "specifications": serializers.IntegerField(),
            "endpoints": serializers.IntegerField(),
            "parameters": serializers.IntegerField(),
        },
    ),
)
class EndpointDiscoveryAPIView(OrganizationContextMixin, APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, IsAnalystRole]

    def post(self, request, *args, **kwargs):
        organization = getattr(request, "current_organization", None)
        projects = project_services.get_projects_for_organization(organization)
        specifications = OpenApiSpecification.objects.filter(project__organization=organization)
        serializer = DiscoverSerializer(
            data=request.data,
            projects=projects,
            specifications=specifications,
        )
        serializer.is_valid(raise_exception=True)
        try:
            summary = services.discover_endpoints(
                project=serializer.validated_data["project"],
                specification=serializer.validated_data.get("specification"),
                imported_by=request.user,
            )
        except ValidationError as exc:
            raise DRFValidationError(exc.messages) from exc
        return Response(summary, status=status.HTTP_200_OK)


router = DefaultRouter()
router.register("endpoints", ApiEndpointViewSet, basename="apishield-endpoint-endpoints")
router.register("endpoint-parameters", EndpointParameterViewSet, basename="apishield-endpoint-parameters")

urlpatterns = [
    path("endpoints/discover/", EndpointDiscoveryAPIView.as_view(), name="apishield-endpoint-discover"),
    path("endpoints/", include(router.urls)),
]
