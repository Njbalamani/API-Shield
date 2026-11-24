from django.contrib.auth import password_validation
from rest_framework import serializers

from organizations.models import Organization

from . import services
from .models import ApiKey, LoginAttempt, User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "full_name", "role", "mfa_enabled", "created_at", "updated_at")
        read_only_fields = fields


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email", "full_name")

    def validate_email(self, value):
        email = services.normalize_email(value)
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return email

    def validate_username(self, value):
        username = value.strip()
        if User.objects.filter(username__iexact=username).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("This username is already taken.")
        return username

    def update(self, instance, validated_data):
        return services.update_profile(
            user=instance,
            email=validated_data["email"],
            username=validated_data["username"],
            full_name=validated_data["full_name"],
        )


class LoginAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginAttempt
        fields = ("id", "email", "ip_address", "success", "created_at")
        read_only_fields = fields


class ApiKeySerializer(serializers.ModelSerializer):
    organization = serializers.SlugRelatedField(slug_field="name", read_only=True)

    class Meta:
        model = ApiKey
        fields = ("id", "name", "organization", "prefix", "is_active", "last_used_at", "revoked_at", "created_at")
        read_only_fields = fields


class ApiKeyCreatedSerializer(ApiKeySerializer):
    raw_key = serializers.CharField(read_only=True)

    class Meta(ApiKeySerializer.Meta):
        fields = ApiKeySerializer.Meta.fields + ("raw_key",)


class ApiKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=120)

    def validate_name(self, value):
        name = value.strip()
        if not name:
            raise serializers.ValidationError("A key name is required.")
        return name

    def create(self, validated_data):
        request = self.context["request"]
        api_key, raw_key = services.create_api_key(
            user=request.user,
            organization=request.current_organization,
            name=validated_data["name"],
        )
        api_key.raw_key = raw_key
        return api_key


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, trim_whitespace=False, style={"input_type": "password"})

    def validate_email(self, value):
        return services.normalize_email(value)


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=150)
    full_name = serializers.CharField(max_length=160)
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, validators=[password_validation.validate_password]
    )
    organization_name = serializers.CharField(max_length=180)
    organization_slug = serializers.SlugField(max_length=200, required=False, allow_blank=True)

    def validate_email(self, value):
        return services.normalize_email(value)

    def create(self, validated_data):
        user, organization = services.register_user(
            email=validated_data["email"],
            username=validated_data["username"],
            full_name=validated_data["full_name"],
            password=validated_data["password"],
            organization_name=validated_data["organization_name"],
            organization_slug=validated_data.get("organization_slug") or None,
        )
        return user


class OrganizationSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "is_active")
        read_only_fields = fields
