from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    report_type_display = serializers.CharField(source="get_report_type_display", read_only=True)
    file_format_display = serializers.CharField(source="get_file_format_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)
    created_by_email = serializers.EmailField(source="created_by.email", read_only=True)

    class Meta:
        model = Report
        fields = (
            "id",
            "organization",
            "project",
            "project_name",
            "scan_run",
            "created_by",
            "created_by_email",
            "report_type",
            "report_type_display",
            "file_format",
            "file_format_display",
            "file",
            "status",
            "status_display",
            "parameters",
            "error_message",
            "created_at",
        )
        read_only_fields = fields


class ChoiceOptionSerializer(serializers.Serializer):
    value = serializers.CharField()
    label = serializers.CharField()


class ReportTypesSerializer(serializers.Serializer):
    report_types = ChoiceOptionSerializer(many=True)
    file_formats = ChoiceOptionSerializer(many=True)


class ReportGenerateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ("project", "scan_run", "report_type", "file_format", "parameters")

    def validate(self, attrs):
        organization = self.context["organization"]
        project = attrs["project"]
        scan_run = attrs.get("scan_run")
        if project.organization_id != organization.id:
            raise serializers.ValidationError("Project does not belong to the current organization.")
        if scan_run is not None and (scan_run.organization_id != organization.id or scan_run.project_id != project.id):
            raise serializers.ValidationError("Scan run does not belong to the selected project.")
        attrs.setdefault("parameters", {})
        return attrs
