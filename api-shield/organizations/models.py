from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=180)
    slug = models.SlugField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_organizations",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class OrganizationMembership(models.Model):
    class Role(models.TextChoices):
        ADMIN = "admin", "Administrator"
        ANALYST = "analyst", "Security Analyst"
        DEVELOPER = "developer", "Developer"
        VIEWER = "viewer", "Viewer"

    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="memberships")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.ANALYST)
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["organization__name", "user__email"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "organization"],
                name="unique_active_user_organization",
                condition=models.Q(is_active=True),
            )
        ]

    def __str__(self):
        return f"{self.user.email} - {self.organization.name} ({self.role})"
