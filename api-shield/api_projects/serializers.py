from django.core.exceptions import ValidationError
from rest_framework import serializers

from organizations.models import Organization

from . import services
from .models import ApiProject, OpenApiSpecification, ScanPolicy
from .services import normalize_base_url


class ScanPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanPolicy
        fields = (
            "allow_passive_tests",
            "allow_active_tests",
            "allow_zap",
            "max_requests",
            "rate_limit_rpm",
            "timeout_seconds",
            "allowed_hosts",
            "updated_at",
        )
        read_only_fields = ("updated_at",)

    def validate(self, attrs):
        project = self.instance.project if self.instance else None
        if attrs.get("allow_active_tests") and project is not None and not project.authorization_confirmed:
            raise serializers.ValidationError("Confirm authorization before enabling active tests.")
        if attrs.get("allow_zap") and not attrs.get("allow_active_tests", False):
            raise serializers.ValidationError("ZAP requires active tests to be enabled.")
        return attrs


class OpenApiSpecificationSerializer(serializers.ModelSerializer):
    project = serializers.SlugRelatedField(slug_field="slug", read_only=True)
    imported_by = serializers.SlugRelatedField(slug_field="email", read_only=True)

    class Meta:
        model = OpenApiSpecification
        fields = (
            "id",
            "project",
            "name",
            "version",
            "source",
            "source_url",
            "raw_content",
            "parsed_data",
            "endpoint_count",
            "imported_by",
            "imported_at",
        )
        read_only_fields = fields


class ApiProjectSerializer(serializers.ModelSerializer):
    organization = serializers.SlugRelatedField(slug_field="slug", read_only=True)
    owner = serializers.SlugRelatedField(slug_field="email", read_only=True)
    endpoint_count = serializers.SerializerMethodField()
    scan_policy = ScanPolicySerializer(read_only=True)

    class Meta:
        model = ApiProject
        fields = (
            "id",
            "organization",
            "name",
            "slug",
            "description",
            "environment",
            "base_url",
            "authorization_confirmed",
            "authorization_reference",
            "status",
            "owner",
            "endpoint_count",
            "scan_policy",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_endpoint_count(self, obj) -> int:
        count = getattr(obj, "endpoint_count", None)
        return count if count is not None else obj.endpoints.count()


class ApiProjectWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiProject
        fields = (
            "name",
            "slug",
            "description",
            "environment",
            "base_url",
            "authorization_confirmed",
            "authorization_reference",
        )
        extra_kwargs = {"slug": {"required": False}}

    def validate_base_url(self, value):
        try:
            return normalize_base_url(value)
        except ValidationError as exc:
            raise serializers.ValidationError(exc.messages) from exc

    def validate(self, attrs):
        organization = self.context["organization"]
        instance = self.instance
        data = dict(attrs)
        data["slug"] = data.get("slug") or (instance.slug if instance else "")
        validated = services.validate_project_data(data, organization=organization, instance=instance)
        attrs.update(validated)
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        return services.create_project(
            organization=self.context["organization"],
            owner=request.user,
            **validated_data,
        )

    def update(self, instance, validated_data):
        return services.update_project(project=instance, data=validated_data)


class SpecUploadSerializer(serializers.Serializer):
    file = serializers.FileField(required=False)
    content = serializers.CharField(required=False, allow_blank=True)
    name = serializers.CharField(max_length=180, required=False, allow_blank=True)

    def validate(self, attrs):
        uploaded = attrs.get("file")
        content = (attrs.get("content") or "").strip()
        if uploaded is not None and content:
            raise serializers.ValidationError("Provide either a file or pasted content, not both.")
        if uploaded is None and not content:
            raise serializers.ValidationError("A specification file or content is required.")
        attrs["content"] = content
        return attrs


class AuthorizationConfirmSerializer(serializers.Serializer):
    authorization_reference = serializers.CharField(max_length=200)

    def validate_authorization_reference(self, value):
        reference = value.strip()
        if not reference:
            raise serializers.ValidationError("An authorization reference is required.")
        return reference


class OrganizationSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ("id", "name", "slug")
        read_only_fields = fields
