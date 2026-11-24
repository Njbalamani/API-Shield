from django.db.models import Count, Q
from django.urls import path
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import generics, serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import HasOrganizationRole, IsOrganizationMember

from .models import ApiRequestLog, BehaviourAlert
from .serializers import AlertActionSerializer, ApiRequestLogSerializer, BehaviourAlertSerializer
from .services import update_alert_status


def _organization(request):
    return getattr(request, "current_organization", None)


class RequestLogListAPIView(generics.ListAPIView):
    serializer_class = ApiRequestLogSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get_queryset(self):
        organization = _organization(self.request)
        if organization is None:
            return ApiRequestLog.objects.none()
        queryset = ApiRequestLog.objects.filter(organization=organization).select_related("project", "endpoint")
        params = self.request.query_params
        if params.get("project"):
            queryset = queryset.filter(project_id=params["project"])
        if params.get("method"):
            queryset = queryset.filter(method=params["method"].upper())
        if params.get("suspicious") in {"1", "true", "True"}:
            queryset = queryset.filter(is_suspicious=True)
        if params.get("status_code"):
            queryset = queryset.filter(status_code=params["status_code"])
        return queryset.order_by("-timestamp")


class BehaviourAlertListAPIView(generics.ListAPIView):
    serializer_class = BehaviourAlertSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get_queryset(self):
        organization = _organization(self.request)
        if organization is None:
            return BehaviourAlert.objects.none()
        queryset = BehaviourAlert.objects.filter(organization=organization).select_related("project", "endpoint")
        params = self.request.query_params
        for field in ("project_id", "alert_type", "status", "severity"):
            value = params.get(field)
            if value:
                queryset = queryset.filter(**{field: value})
        return queryset.order_by("-created_at")


class BehaviourAlertDetailAPIView(generics.RetrieveAPIView):
    serializer_class = BehaviourAlertSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get_queryset(self):
        organization = _organization(self.request)
        if organization is None:
            return BehaviourAlert.objects.none()
        return BehaviourAlert.objects.filter(organization=organization).select_related("project", "endpoint")


@extend_schema(request=AlertActionSerializer, responses=BehaviourAlertSerializer)
class BehaviourAlertActionAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def post(self, request, pk):
        organization = _organization(request)
        alert = BehaviourAlert.objects.filter(pk=pk, organization=organization).first() if organization else None
        if alert is None:
            return Response({"detail": "Alert not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = AlertActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = (
            BehaviourAlert.Status.ACKNOWLEDGED
            if serializer.validated_data["action"] == "acknowledge"
            else BehaviourAlert.Status.RESOLVED
        )
        update_alert_status(alert, target, request.user)
        return Response(BehaviourAlertSerializer(alert).data)


@extend_schema(
    responses=inline_serializer(
        name="BehaviourSummary",
        fields={
            "total_requests": serializers.IntegerField(),
            "suspicious_requests": serializers.IntegerField(),
            "failed_requests": serializers.IntegerField(),
            "total_alerts": serializers.IntegerField(),
            "open_alerts": serializers.IntegerField(),
            "alerts_by_type": inline_serializer(
                name="BehaviourAlertTypeCount",
                fields={
                    "alert_type": serializers.CharField(),
                    "count": serializers.IntegerField(),
                },
                many=True,
            ),
            "suspicious_by_project": inline_serializer(
                name="BehaviourSuspiciousProjectCount",
                fields={
                    "project__name": serializers.CharField(allow_null=True),
                    "count": serializers.IntegerField(),
                },
                many=True,
            ),
            "recent_failures": serializers.IntegerField(),
        },
    )
)
class BehaviourSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember, HasOrganizationRole]
    required_role = "analyst"

    def get(self, request):
        organization = _organization(request)
        if organization is None:
            return Response({"detail": "No active organization."}, status=status.HTTP_400_BAD_REQUEST)
        logs = ApiRequestLog.objects.filter(organization=organization)
        alerts = BehaviourAlert.objects.filter(organization=organization)
        return Response(
            {
                "total_requests": logs.count(),
                "suspicious_requests": logs.filter(is_suspicious=True).count(),
                "failed_requests": logs.filter(status_code__gte=400).count(),
                "total_alerts": alerts.count(),
                "open_alerts": alerts.filter(status=BehaviourAlert.Status.OPEN).count(),
                "alerts_by_type": list(alerts.values("alert_type").annotate(count=Count("id")).order_by("alert_type")),
                "suspicious_by_project": list(
                    logs.filter(is_suspicious=True)
                    .values("project__name")
                    .annotate(count=Count("id"))
                    .order_by("-count")
                ),
                "recent_failures": logs.filter(Q(status_code__gte=500)).count(),
            }
        )


urlpatterns = [
    path("behaviour/logs/", RequestLogListAPIView.as_view(), name="apishield-behaviour-logs"),
    path("behaviour/alerts/", BehaviourAlertListAPIView.as_view(), name="apishield-behaviour-alerts"),
    path("behaviour/alerts/<int:pk>/", BehaviourAlertDetailAPIView.as_view(), name="apishield-behaviour-alert-detail"),
    path(
        "behaviour/alerts/<int:pk>/action/",
        BehaviourAlertActionAPIView.as_view(),
        name="apishield-behaviour-alert-action",
    ),
    path("behaviour/summary/", BehaviourSummaryAPIView.as_view(), name="apishield-behaviour-summary"),
]
