from django.core.exceptions import PermissionDenied
from django.urls import include, path
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsAdminRole, IsOrganizationMember
from accounts.services import resolve_request_organization

from . import services
from .serializers import (
    MemberAddSerializer,
    OrganizationMembershipSerializer,
    OrganizationSerializer,
    OrganizationSwitchSerializer,
    OrganizationWriteSerializer,
)


class OrganizationContextMixin:
    def initial(self, request, *args, **kwargs):
        resolve_request_organization(request)
        return super().initial(request, *args, **kwargs)


class OrganizationViewSet(OrganizationContextMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ("name", "slug", "description")
    ordering_fields = ("name", "created_at")

    def get_queryset(self):
        return services.get_user_organizations(self.request.user)

    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return OrganizationWriteSerializer
        return OrganizationSerializer

    def get_permissions(self):
        if self.action == "add_member":
            return [IsAuthenticated(), IsOrganizationMember(), IsAdminRole()]
        return super().get_permissions()

    @action(detail=True, methods=["post"], url_path="switch", url_name="switch")
    def switch(self, request, pk=None):
        organization = services.switch_organization(user=request.user, organization_id=pk)
        request.session["active_organization_id"] = str(organization.pk)
        return Response(OrganizationSerializer(organization).data)

    @action(detail=True, methods=["get"], url_path="members", url_name="members")
    def members(self, request, pk=None):
        organization = self.get_object()
        serializer = OrganizationMembershipSerializer(services.list_members(organization=organization), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="members/add", url_name="add-member")
    def add_member(self, request, pk=None):
        organization = services.get_organization_for_user(request.user, pk)
        if organization is None:
            raise PermissionDenied("You are not a member of that organization.")
        serializer = MemberAddSerializer(data=request.data, context={"organization": organization})
        serializer.is_valid(raise_exception=True)
        membership = serializer.save()
        return Response(OrganizationMembershipSerializer(membership).data, status=status.HTTP_201_CREATED)


class OrganizationMembershipViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = OrganizationMembershipSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]

    def get_queryset(self):
        return services.list_members(organization=getattr(self.request, "current_organization", None))


@extend_schema(request=OrganizationSwitchSerializer, responses=OrganizationSerializer)
class OrganizationSwitchAPIView(OrganizationContextMixin, APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = OrganizationSwitchSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        organization = services.switch_organization(
            user=request.user,
            organization_id=serializer.validated_data["organization_id"],
        )
        request.session["active_organization_id"] = str(organization.pk)
        return Response(OrganizationSerializer(organization).data)


router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="apishield-org-organizations")
router.register("memberships", OrganizationMembershipViewSet, basename="apishield-org-memberships")

urlpatterns = [
    path("organizations/switch/", OrganizationSwitchAPIView.as_view(), name="apishield-org-switch"),
    path("organizations/", include(router.urls)),
]
