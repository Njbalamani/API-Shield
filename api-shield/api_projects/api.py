from django.core.exceptions import PermissionDenied
from django.urls import include, path
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter

from accounts.permissions import HasOrganizationRole, IsAdminRole, IsOrganizationMember
from accounts.services import resolve_request_organization
from endpoint_discovery.services import import_openapi_spec

from . import services
from .models import OpenApiSpecification, ScanPolicy
from .serializers import (
    ApiProjectSerializer,
    ApiProjectWriteSerializer,
    AuthorizationConfirmSerializer,
    OpenApiSpecificationSerializer,
    ScanPolicySerializer,
    SpecUploadSerializer,
)


class OrganizationContextMixin:
    def initial(self, request, *args, **kwargs):
        resolve_request_organization(request)
        return super().initial(request, *args, **kwargs)


class ApiProjectViewSet(OrganizationContextMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ("name", "slug", "description")
    ordering_fields = ("name", "created_at", "updated_at")

    def get_queryset(self):
        return services.get_projects_for_organization(getattr(self.request, "current_organization", None))

    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return ApiProjectWriteSerializer
        return ApiProjectSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["organization"] = getattr(self.request, "current_organization", None)
        return context

    def get_permissions(self):
        if self.action == "destroy":
            return [IsAuthenticated(), IsOrganizationMember(), IsAdminRole()]
        return super().get_permissions()

    @action(detail=True, methods=["post"], url_path="spec-upload", url_name="spec-upload")
    def spec_upload(self, request, pk=None):
        project = self.get_object()
        if not project.authorization_confirmed:
            raise PermissionDenied("Confirm authorization before importing a specification.")
        serializer = SpecUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        specification = import_openapi_spec(
            project=project,
            uploaded_file=serializer.validated_data.get("file"),
            content=serializer.validated_data.get("content") or None,
            name=serializer.validated_data.get("name") or None,
            imported_by=request.user,
        )
        return Response(OpenApiSpecificationSerializer(specification).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="confirm-authorization", url_name="confirm-authorization")
    def confirm_authorization(self, request, pk=None):
        project = self.get_object()
        serializer = AuthorizationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = services.confirm_authorization(
            project=project,
            reference=serializer.validated_data["authorization_reference"],
        )
        return Response(ApiProjectSerializer(project).data)


class ScanPolicyViewSet(
    OrganizationContextMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = ScanPolicySerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, IsAdminRole]
    http_method_names = ["get", "patch", "put", "head", "options"]

    def get_queryset(self):
        return ScanPolicy.objects.filter(
            project__organization=getattr(self.request, "current_organization", None)
        ).select_related("project")


class OpenApiSpecificationViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = OpenApiSpecificationSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    filter_backends = [OrderingFilter]
    ordering_fields = ("imported_at", "name")

    def get_queryset(self):
        queryset = OpenApiSpecification.objects.filter(
            project__organization=getattr(self.request, "current_organization", None)
        )
        project_id = self.request.query_params.get("project")
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset.select_related("project", "imported_by")


router = DefaultRouter()
router.register("projects", ApiProjectViewSet, basename="apishield-project-projects")
router.register("scan-policies", ScanPolicyViewSet, basename="apishield-project-scan-policies")
router.register("specifications", OpenApiSpecificationViewSet, basename="apishield-project-specifications")

urlpatterns = [
    path("projects/", include(router.urls)),
]
