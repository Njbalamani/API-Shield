from django.contrib import admin

from .models import Organization, OrganizationMembership


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "created_by", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "slug", "description")
    readonly_fields = ("created_at", "updated_at")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "is_active", "joined_at")
    list_filter = ("role", "is_active", "organization")
    search_fields = ("user__email", "organization__name")
    readonly_fields = ("joined_at",)
    raw_id_fields = ("user", "organization")
