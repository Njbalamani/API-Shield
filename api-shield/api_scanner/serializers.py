from rest_framework import serializers

from accounts.permissions import has_minimum_role
from api_projects.models import ApiProject, OpenApiSpecification

from .models import ScanFinding, ScanLog, ScanRule, ScanRun


class OrganizationContextMixin:
    def organization(self):
        request = self.context.get("request")
        return getattr(request, "current_organization", None) if request else None

    def user(self):
        request = self.context.get("request")
        return getattr(request, "user", None)


class ScanRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRule
        fields = (
            "id",
            "rule_id",
            "title",
            "description",
            "category",
            "severity",
            "confidence",
            "owasp_category",
            "cwe",
            "engine",
            "remediation",
            "enabled",
        )
        read_only_fields = fields


class ScanRunSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    initiated_by_email = serializers.CharField(source="initiated_by.email", read_only=True, allow_null=True)

    class Meta:
        model = ScanRun
        fields = (
            "id",
            "organization",
            "project",
            "project_name",
            "specification",
            "initiated_by",
            "initiated_by_email",
            "status",
            "mode",
            "started_at",
            "finished_at",
            "endpoints_count",
            "findings_count",
            "critical_count",
            "high_count",
            "risk_score",
            "authorization_verified",
            "summary",
            "error_message",
        )
        read_only_fields = fields


class ScanFindingSerializer(serializers.ModelSerializer):
    scan_run_id = serializers.IntegerField(source="scan_run.id", read_only=True)
    endpoint_path = serializers.CharField(source="endpoint.path", read_only=True, allow_null=True)

    class Meta:
        model = ScanFinding
        fields = (
            "id",
            "scan_run",
            "scan_run_id",
            "endpoint",
            "endpoint_path",
            "rule",
            "title",
            "description",
            "severity",
            "confidence",
            "owasp_category",
            "cwe",
            "status",
            "evidence",
            "request",
            "response",
            "remediation",
            "verified",
            "risk_score",
            "is_synthetic",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "scan_run",
            "scan_run_id",
            "endpoint",
            "endpoint_path",
            "rule",
            "created_at",
            "updated_at",
        )


class ScanFindingStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanFinding
        fields = ("status",)


class ScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanLog
        fields = ("id", "scan_run", "level", "message", "context", "created_at")
        read_only_fields = fields


class ScanStartSerializer(OrganizationContextMixin, serializers.Serializer):
    project = serializers.PrimaryKeyRelatedField(queryset=ApiProject.objects.all())
    specification = serializers.PrimaryKeyRelatedField(
        queryset=OpenApiSpecification.objects.all(), required=False, allow_null=True
    )
    mode = serializers.ChoiceField(choices=ScanRun.Mode.choices, default=ScanRun.Mode.PASSIVE)

    def validate_project(self, value):
        organization = self.organization()
        if organization is not None and value.organization_id != organization.id:
            raise serializers.ValidationError("The project is outside the active organization.")
        if not has_minimum_role(self.user(), value.organization, "analyst"):
            raise serializers.ValidationError("You do not have permission to scan this organization.")
        if value.status != ApiProject.Status.ACTIVE:
            raise serializers.ValidationError("Only active projects can be scanned.")
        return value

    def validate(self, attrs):
        specification = attrs.get("specification")
        project = attrs.get("project")
        if specification is not None and project is not None and specification.project_id != project.id:
            raise serializers.ValidationError("The specification does not belong to the selected project.")
        return attrs
