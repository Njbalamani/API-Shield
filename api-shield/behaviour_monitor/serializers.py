from rest_framework import serializers

from .models import ApiRequestLog, BehaviourAlert


class ApiRequestLogSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    endpoint_label = serializers.SerializerMethodField()

    class Meta:
        model = ApiRequestLog
        fields = (
            "id",
            "organization",
            "project",
            "project_name",
            "endpoint",
            "endpoint_label",
            "method",
            "path",
            "ip_address",
            "status_code",
            "response_time_ms",
            "query_keys",
            "is_suspicious",
            "timestamp",
        )
        read_only_fields = fields

    def get_endpoint_label(self, obj) -> str | None:
        return str(obj.endpoint) if obj.endpoint_id else None


class BehaviourAlertSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    endpoint_label = serializers.SerializerMethodField()
    alert_type_display = serializers.CharField(source="get_alert_type_display", read_only=True)
    severity_display = serializers.CharField(source="get_severity_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = BehaviourAlert
        fields = (
            "id",
            "organization",
            "project",
            "project_name",
            "endpoint",
            "endpoint_label",
            "alert_type",
            "alert_type_display",
            "severity",
            "severity_display",
            "title",
            "description",
            "evidence",
            "status",
            "status_display",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_endpoint_label(self, obj) -> str | None:
        return str(obj.endpoint) if obj.endpoint_id else None


class AlertActionSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=(("acknowledge", "Acknowledge"), ("resolve", "Resolve")))
