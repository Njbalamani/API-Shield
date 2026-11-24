from django.db import models


class ApiRequestLog(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="request_logs"
    )
    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="request_logs")
    endpoint = models.ForeignKey(
        "endpoint_discovery.ApiEndpoint",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="request_logs",
    )
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    status_code = models.PositiveIntegerField(null=True, blank=True)
    response_time_ms = models.PositiveIntegerField(default=0)
    query_keys = models.JSONField(default=list)
    is_suspicious = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["project", "timestamp"]),
            models.Index(fields=["ip_address", "timestamp"]),
            models.Index(fields=["is_suspicious", "timestamp"]),
        ]

    def __str__(self):
        return f"{self.method} {self.path} {self.status_code or ''}".strip()


class BehaviourAlert(models.Model):
    class AlertType(models.TextChoices):
        HIGH_FREQUENCY = "high_frequency", "High Request Frequency"
        REPEATED_FAILURES = "repeated_failures", "Repeated Failed Requests"
        SENSITIVE_ENDPOINT = "sensitive_endpoint", "Sensitive Endpoint Access"
        UNUSUAL_PATTERN = "unusual_pattern", "Unusual Request Pattern"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        RESOLVED = "resolved", "Resolved"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="behaviour_alerts"
    )
    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="behaviour_alerts")
    endpoint = models.ForeignKey(
        "endpoint_discovery.ApiEndpoint",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="behaviour_alerts",
    )
    alert_type = models.CharField(max_length=30, choices=AlertType.choices)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MEDIUM)
    title = models.CharField(max_length=220)
    description = models.TextField()
    evidence = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title
