from django.conf import settings
from django.contrib.auth import login as django_login
from django.core.exceptions import PermissionDenied
from django.urls import include, path
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsAdminRole, IsDeveloperRole, IsOrganizationMember

from . import services
from .models import ApiKey, LoginAttempt, User
from .serializers import (
    ApiKeyCreatedSerializer,
    ApiKeyCreateSerializer,
    ApiKeySerializer,
    LoginAttemptSerializer,
    LoginSerializer,
    ProfileUpdateSerializer,
    RegisterSerializer,
    UserSerializer,
)


class OrganizationContextMixin:
    def initial(self, request, *args, **kwargs):
        services.resolve_request_organization(request)
        return super().initial(request, *args, **kwargs)


class UserViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ("email", "username", "full_name")
    ordering_fields = ("email", "full_name", "created_at")

    def get_queryset(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return User.objects.none()
        return User.objects.filter(memberships__organization=organization, memberships__is_active=True).distinct()

    def get_permissions(self):
        if self.action == "me":
            return [IsAuthenticated()]
        return super().get_permissions()

    @action(detail=False, methods=["get", "patch"], url_path="me", url_name="me")
    def me(self, request, pk=None):
        if request.method == "PATCH":
            serializer = ProfileUpdateSerializer(request.user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response(UserSerializer(user).data)
        return Response(UserSerializer(request.user).data)


class ApiKeyViewSet(OrganizationContextMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationMember, IsDeveloperRole]
    required_role = "developer"
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return ApiKey.objects.none()
        return ApiKey.objects.filter(user=self.request.user, organization=organization).select_related("organization")

    def get_serializer_class(self):
        if self.action == "create":
            return ApiKeyCreateSerializer
        return ApiKeySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        api_key = serializer.save()
        return Response(ApiKeyCreatedSerializer(api_key).data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        services.revoke_api_key(api_key=self.get_object(), user=request.user)
        return Response(ApiKeySerializer(self.get_object()).data)

    @action(detail=True, methods=["post"], url_path="revoke", url_name="revoke")
    def revoke(self, request, pk=None):
        api_key = services.revoke_api_key(api_key=self.get_object(), user=request.user)
        return Response(ApiKeySerializer(api_key).data)


class LoginAttemptViewSet(OrganizationContextMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = LoginAttemptSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, IsAdminRole]
    filter_backends = [OrderingFilter]
    ordering_fields = ("created_at", "email")

    def get_queryset(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return LoginAttempt.objects.none()
        emails = User.objects.filter(memberships__organization=organization, memberships__is_active=True).values_list(
            "email", flat=True
        )
        return LoginAttempt.objects.filter(email__in=emails)


@extend_schema(request=LoginSerializer, responses=UserSerializer)
class LoginAPIView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user, reason = services.login_user(
            request=request,
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )
        if user is None:
            if reason == "locked":
                return Response({"detail": "Too many failed attempts. Try again in 15 minutes."}, status=429)
            return Response({"detail": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
        underlying = getattr(request, "_request", request)
        django_login(underlying, user)
        if hasattr(request, "_request"):
            request._user = user
        return Response(UserSerializer(user).data)


@extend_schema(request=RegisterSerializer, responses={status.HTTP_201_CREATED: UserSerializer})
class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user = getattr(request, "user", None)
        if not settings.ALLOW_PUBLIC_REGISTRATION and not (user is not None and user.is_superuser):
            raise PermissionDenied("Public registration is disabled.")
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        created_user = serializer.save()
        return Response(UserSerializer(created_user).data, status=status.HTTP_201_CREATED)


@extend_schema(request=ProfileUpdateSerializer, responses=UserSerializer)
class CurrentUserAPIView(OrganizationContextMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(UserSerializer(request.user).data)

    def patch(self, request, *args, **kwargs):
        serializer = ProfileUpdateSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        return Response(UserSerializer(serializer.save()).data)


router = DefaultRouter()
router.register("users", UserViewSet, basename="apishield-account-users")
router.register("api-keys", ApiKeyViewSet, basename="apishield-account-api-keys")
router.register("login-attempts", LoginAttemptViewSet, basename="apishield-account-login-attempts")

urlpatterns = [
    path("accounts/login/", LoginAPIView.as_view(), name="apishield-account-login"),
    path("accounts/register/", RegisterAPIView.as_view(), name="apishield-account-register"),
    path("accounts/me/", CurrentUserAPIView.as_view(), name="apishield-account-me"),
    path("accounts/", include(router.urls)),
]
