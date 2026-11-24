from pathlib import Path
from uuid import uuid4

from django.core.validators import FileExtensionValidator
from django.db import models


def specification_upload_path(instance, filename):
    safe_name = Path(filename).name
    suffix = Path(safe_name).suffix.lower()
    return f"openapi/{uuid4().hex}{suffix}"


class ApiProject(models.Model):
    class Environment(models.TextChoices):
        DEVELOPMENT = "development", "Development"
        STAGING = "staging", "Staging"
        PRODUCTION = "production", "Production"
        CONTROLLED_LAB = "controlled_lab", "Controlled Lab"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=180)
    slug = models.SlugField(max_length=200)
    description = models.TextField(blank=True)
    environment = models.CharField(max_length=20, choices=Environment.choices, default=Environment.CONTROLLED_LAB)
    base_url = models.URLField(max_length=500, blank=True)
    authorization_confirmed = models.BooleanField(default=False)
    authorization_reference = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    owner = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="owned_projects",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["organization", "slug"], name="unique_project_slug_per_org")]

    def __str__(self):
        return self.name


class OpenApiSpecification(models.Model):
    class Source(models.TextChoices):
        FILE = "file", "File Upload"
        URL = "url", "Remote URL"
        PASTED = "pasted", "Pasted Text"

    project = models.ForeignKey(ApiProject, on_delete=models.CASCADE, related_name="specifications")
    name = models.CharField(max_length=180)
    version = models.CharField(max_length=80, blank=True)
    source = models.CharField(max_length=20, choices=Source.choices, default=Source.FILE)
    source_url = models.URLField(max_length=500, blank=True)
    file = models.FileField(
        upload_to=specification_upload_path,
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=["json", "yaml", "yml", "txt"])],
    )
    raw_content = models.TextField(blank=True)
    parsed_data = models.JSONField(default=dict)
    endpoint_count = models.PositiveIntegerField(default=0)
    imported_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="imported_specifications",
    )
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-imported_at"]

    def __str__(self):
        return self.name


class ScanPolicy(models.Model):
    project = models.OneToOneField(ApiProject, on_delete=models.CASCADE, related_name="scan_policy")
    allow_passive_tests = models.BooleanField(default=True)
    allow_active_tests = models.BooleanField(default=False)
    allow_zap = models.BooleanField(default=False)
    max_requests = models.PositiveIntegerField(default=40)
    rate_limit_rpm = models.PositiveIntegerField(default=30)
    timeout_seconds = models.PositiveIntegerField(default=15)
    allowed_hosts = models.TextField(
        blank=True,
        help_text="Comma-separated hostnames explicitly approved for active testing.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Scan policy - {self.project.name}"
