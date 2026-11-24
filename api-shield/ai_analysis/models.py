from django.db import models


class AiAnalysis(models.Model):
    class Source(models.TextChoices):
        LOCAL = "local", "Local Model"
        GEMINI = "gemini", "Google Gemini"
        HYBRID = "hybrid", "Hybrid"

    finding = models.OneToOneField(
        "api_scanner.ScanFinding",
        on_delete=models.CASCADE,
        related_name="ai_analysis",
    )
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="ai_analyses")
    explanation = models.TextField()
    remediation = models.TextField()
    code_example = models.TextField(blank=True)
    risk_score = models.FloatField(default=0)
    priority = models.CharField(max_length=20, default="medium")
    model_name = models.CharField(max_length=120, default="local-risk-model")
    source = models.CharField(max_length=20, choices=Source.choices, default=Source.LOCAL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"AI analysis - {self.finding.title}"
