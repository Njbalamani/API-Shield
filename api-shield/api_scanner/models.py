from django.db import models


class ScanRule(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Engine(models.TextChoices):
        CUSTOM = "custom", "Custom Scanner"
        ZAP = "zap", "OWASP ZAP"
        AUTH = "authentication", "Authentication Audit"
        BEHAVIOUR = "behaviour", "Behaviour Monitor"

    rule_id = models.CharField(max_length=80, unique=True)
    title = models.CharField(max_length=220)
    description = models.TextField()
    category = models.CharField(max_length=120)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MEDIUM)
    confidence = models.CharField(max_length=20, default="medium")
    owasp_category = models.CharField(max_length=120, blank=True)
    cwe = models.CharField(max_length=40, blank=True)
    engine = models.CharField(max_length=30, choices=Engine.choices, default=Engine.CUSTOM)
    remediation = models.JSONField(default=dict)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["category", "rule_id"]

    def __str__(self):
        return f"{self.rule_id} - {self.title}"


class ScanRun(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class Mode(models.TextChoices):
        PASSIVE = "passive", "Passive Analysis"
        ACTIVE = "active", "Controlled Active Testing"
        ZAP = "zap", "OWASP ZAP"
        FULL = "full", "Full Assessment"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="scan_runs")
    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="scan_runs")
    specification = models.ForeignKey(
        "api_projects.OpenApiSpecification",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_runs",
    )
    initiated_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="scan_runs",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    mode = models.CharField(max_length=20, choices=Mode.choices, default=Mode.PASSIVE)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    endpoints_count = models.PositiveIntegerField(default=0)
    findings_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    risk_score = models.FloatField(default=0)
    authorization_verified = models.BooleanField(default=False)
    summary = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Scan #{self.id} - {self.project.name}"


class ScanFinding(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        IN_PROGRESS = "in_progress", "In Progress"
        RESOLVED = "resolved", "Resolved"
        FALSE_POSITIVE = "false_positive", "False Positive"
        ACCEPTED_RISK = "accepted_risk", "Accepted Risk"

    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="findings")
    endpoint = models.ForeignKey(
        "endpoint_discovery.ApiEndpoint",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    rule = models.ForeignKey(ScanRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="findings")
    title = models.CharField(max_length=240)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MEDIUM)
    confidence = models.CharField(max_length=20, default="medium")
    owasp_category = models.CharField(max_length=120, blank=True)
    cwe = models.CharField(max_length=40, blank=True)
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.OPEN)
    evidence = models.JSONField(default=dict)
    request = models.JSONField(default=dict)
    response = models.JSONField(default=dict)
    remediation = models.JSONField(default=dict)
    verified = models.BooleanField(default=False)
    risk_score = models.FloatField(default=0)
    is_synthetic = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score", "-created_at"]

    def __str__(self):
        return self.title


class ScanLog(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=20, default="INFO")
    message = models.TextField()
    context = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.level}: {self.message[:60]}"
