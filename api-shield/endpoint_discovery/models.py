from django.db import models


class ApiEndpoint(models.Model):
    class Method(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"
        OPTIONS = "OPTIONS", "OPTIONS"
        HEAD = "HEAD", "HEAD"

    class RiskLevel(models.TextChoices):
        NONE = "none", "None"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="endpoints")
    specification = models.ForeignKey(
        "api_projects.OpenApiSpecification",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="endpoints",
    )
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10, choices=Method.choices)
    operation_id = models.CharField(max_length=180, blank=True)
    summary = models.CharField(max_length=300, blank=True)
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list)
    parameters = models.JSONField(default=list)
    security = models.JSONField(default=list)
    request_schema = models.JSONField(default=dict)
    response_schema = models.JSONField(default=dict)
    auth_required = models.BooleanField(default=False)
    auth_schemes = models.JSONField(default=list)
    risk_level = models.CharField(max_length=20, choices=RiskLevel.choices, default=RiskLevel.NONE)
    is_active = models.BooleanField(default=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path", "method"]
        constraints = [
            models.UniqueConstraint(fields=["project", "path", "method"], name="unique_endpoint_per_project")
        ]

    def __str__(self):
        return f"{self.method} {self.path}"


class EndpointParameter(models.Model):
    class Location(models.TextChoices):
        PATH = "path", "Path"
        QUERY = "query", "Query"
        HEADER = "header", "Header"
        COOKIE = "cookie", "Cookie"
        BODY = "body", "Body"

    endpoint = models.ForeignKey(ApiEndpoint, on_delete=models.CASCADE, related_name="endpoint_parameters")
    name = models.CharField(max_length=180)
    location = models.CharField(max_length=20, choices=Location.choices)
    required = models.BooleanField(default=False)
    schema = models.JSONField(default=dict)
    example = models.TextField(blank=True)
    sensitive = models.BooleanField(default=False)

    class Meta:
        ordering = ["location", "name"]
        constraints = [
            models.UniqueConstraint(fields=["endpoint", "name", "location"], name="unique_parameter_per_endpoint")
        ]

    def __str__(self):
        return f"{self.location}:{self.name}"
