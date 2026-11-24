from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        FULL = "full", "Full Security Assessment"
        ENDPOINT = "endpoint", "API Endpoint Report"
        OWASP = "owasp", "OWASP Vulnerability Summary"
        AUTH = "authentication", "Authentication Audit Report"
        BEHAVIOUR = "behaviour", "Behaviour Monitoring Report"

    class FileFormat(models.TextChoices):
        PDF = "pdf", "PDF"
        JSON = "json", "JSON"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="reports")
    project = models.ForeignKey("api_projects.ApiProject", on_delete=models.CASCADE, related_name="reports")
    scan_run = models.ForeignKey(
        "api_scanner.ScanRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    created_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="reports",
    )
    report_type = models.CharField(max_length=30, choices=ReportType.choices, default=ReportType.FULL)
    file_format = models.CharField(max_length=10, choices=FileFormat.choices, default=FileFormat.PDF)
    file = models.FileField(upload_to="reports/", blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    parameters = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_report_type_display()} ({self.file_format.upper()})"

    def delete(self, *args, **kwargs):
        file_name = self.file.name if self.file else None
        result = super().delete(*args, **kwargs)
        if file_name:
            self.file.storage.delete(file_name)
        return result
