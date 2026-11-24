from django.db import models


class AuthenticationAudit(models.Model):
    class AuthType(models.TextChoices):
        JWT = "jwt", "JWT"
        OAUTH2 = "oauth2", "OAuth 2.0"
        API_KEY = "api_key", "API Key"
        BASIC = "basic", "Basic Auth"
        NONE = "none", "No Authentication"
        UNKNOWN = "unknown", "Unknown"

    class Result(models.TextChoices):
        PASS = "pass", "Pass"
        WARN = "warn", "Warning"
        FAIL = "fail", "Fail"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="auth_audits")
    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="auth_audits")
    scan_run = models.ForeignKey(
        "api_scanner.ScanRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_audits",
    )
    endpoint = models.ForeignKey(
        "endpoint_discovery.ApiEndpoint",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_audits",
    )
    auth_type = models.CharField(max_length=20, choices=AuthType.choices, default=AuthType.UNKNOWN)
    result = models.CharField(max_length=10, choices=Result.choices, default=Result.PASS)
    expiration_detected = models.BooleanField(default=False)
    insecure_token_handling = models.BooleanField(default=False)
    authorization_controls = models.BooleanField(default=False)
    findings = models.JSONField(default=list)
    score = models.FloatField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Auth audit - {self.endpoint or self.project}"


class TokenTest(models.Model):
    audit = models.ForeignKey(AuthenticationAudit, on_delete=models.CASCADE, related_name="token_tests")
    name = models.CharField(max_length=180)
    outcome = models.CharField(max_length=20)
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.name
