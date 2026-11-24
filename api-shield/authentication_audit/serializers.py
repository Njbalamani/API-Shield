from rest_framework import serializers

from api_projects.models import ApiProject
from api_scanner.models import ScanRun

from .models import AuthenticationAudit, TokenTest


class TokenTestSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenTest
        fields = ("id", "audit", "name", "outcome", "evidence", "created_at")
        read_only_fields = fields


class AuthenticationAuditSerializer(serializers.ModelSerializer):
    token_tests = TokenTestSerializer(many=True, read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)
    endpoint_path = serializers.CharField(source="endpoint.path", read_only=True, allow_null=True)

    class Meta:
        model = AuthenticationAudit
        fields = (
            "id",
            "organization",
            "project",
            "project_name",
            "scan_run",
            "endpoint",
            "endpoint_path",
            "auth_type",
            "result",
            "expiration_detected",
            "insecure_token_handling",
            "authorization_controls",
            "findings",
            "score",
            "created_at",
            "token_tests",
        )
        read_only_fields = fields


class AuditRunSerializer(serializers.Serializer):
    project = serializers.PrimaryKeyRelatedField(queryset=ApiProject.objects.all())
    scan_run = serializers.PrimaryKeyRelatedField(queryset=ScanRun.objects.all(), required=False, allow_null=True)

    def validate(self, attrs):
        project = attrs.get("project")
        scan_run = attrs.get("scan_run")
        if scan_run is not None and project is not None and scan_run.project_id != project.id:
            raise serializers.ValidationError("The selected scan does not belong to the selected project.")
        request = self.context.get("request")
        organization = getattr(request, "current_organization", None) if request else None
        if organization is not None and project is not None and project.organization_id != organization.id:
            raise serializers.ValidationError("The project is outside the active organization.")
        return attrs
