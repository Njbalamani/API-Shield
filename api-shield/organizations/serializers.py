from rest_framework import serializers

from accounts.serializers import UserSerializer

from .models import Organization, OrganizationMembership


class OrganizationSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = (
            "id",
            "name",
            "slug",
            "description",
            "is_active",
            "created_at",
            "updated_at",
            "member_count",
        )
        read_only_fields = fields

    def get_member_count(self, obj) -> int:
        return obj.memberships.filter(is_active=True).count()


class OrganizationWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ("name", "slug", "description")

    def create(self, validated_data):
        from .services import create_organization

        return create_organization(created_by=self.context["request"].user, **validated_data)


class OrganizationMembershipSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    organization = serializers.SlugRelatedField(slug_field="slug", read_only=True)

    class Meta:
        model = OrganizationMembership
        fields = ("id", "organization", "user", "role", "is_active", "joined_at")
        read_only_fields = fields


class MemberAddSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=OrganizationMembership.Role.choices)

    def validate_email(self, value):
        return value.strip().lower()

    def create(self, validated_data):
        from .services import add_member

        return add_member(
            organization=self.context["organization"],
            email=validated_data["email"],
            role=validated_data["role"],
        )


class OrganizationSwitchSerializer(serializers.Serializer):
    organization_id = serializers.IntegerField()

    def validate_organization_id(self, value):
        from .services import get_organization_for_user

        request = self.context["request"]
        if get_organization_for_user(request.user, value) is None:
            raise serializers.ValidationError("You are not a member of that organization.")
        return value
