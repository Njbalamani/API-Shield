from rest_framework import serializers

from api_projects.models import ApiProject, OpenApiSpecification

from .models import ApiEndpoint, EndpointParameter


class EndpointParameterSerializer(serializers.ModelSerializer):
    endpoint = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = EndpointParameter
        fields = ("id", "endpoint", "name", "location", "required", "schema", "example", "sensitive")
        read_only_fields = fields


class ApiEndpointSerializer(serializers.ModelSerializer):
    project = serializers.SlugRelatedField(slug_field="slug", read_only=True)
    specification = serializers.PrimaryKeyRelatedField(read_only=True)
    endpoint_parameters = EndpointParameterSerializer(many=True, read_only=True)

    class Meta:
        model = ApiEndpoint
        fields = (
            "id",
            "project",
            "specification",
            "path",
            "method",
            "operation_id",
            "summary",
            "description",
            "tags",
            "parameters",
            "security",
            "request_schema",
            "response_schema",
            "auth_required",
            "auth_schemes",
            "risk_level",
            "is_active",
            "discovered_at",
            "updated_at",
            "endpoint_parameters",
        )
        read_only_fields = fields


class DiscoverSerializer(serializers.Serializer):
    project = serializers.PrimaryKeyRelatedField(queryset=ApiProject.objects.none())
    specification = serializers.PrimaryKeyRelatedField(
        queryset=OpenApiSpecification.objects.none(), required=False, allow_null=True
    )

    def __init__(self, *args, projects=None, specifications=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].queryset = projects if projects is not None else ApiProject.objects.none()
        self.fields["specification"].queryset = (
            specifications if specifications is not None else OpenApiSpecification.objects.none()
        )

    def validate(self, attrs):
        project = attrs.get("project")
        specification = attrs.get("specification")
        if specification is not None and project is not None and specification.project_id != project.pk:
            raise serializers.ValidationError("The specification does not belong to the selected project.")
        return attrs
