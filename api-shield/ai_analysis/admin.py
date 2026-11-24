from django.contrib import admin

from .models import AiAnalysis


@admin.register(AiAnalysis)
class AiAnalysisAdmin(admin.ModelAdmin):
    list_display = ("id", "finding", "organization", "risk_score", "priority", "source", "model_name", "updated_at")
    list_filter = ("priority", "source", "model_name", "organization")
    search_fields = ("finding__title", "explanation", "remediation", "model_name")
    readonly_fields = ("created_at", "updated_at")

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "organization":
            from accounts.permissions import user_organizations

            kwargs["queryset"] = user_organizations(request.user)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)
