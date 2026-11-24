from rest_framework import serializers

from api_scanner.models import ScanFinding, ScanRun

from .models import AiAnalysis


class AiAnalysisSerializer(serializers.ModelSerializer):
    finding_title = serializers.CharField(source="finding.title", read_only=True)
    scan_run_id = serializers.IntegerField(source="finding.scan_run_id", read_only=True)

    class Meta:
        model = AiAnalysis
        fields = (
            "id",
            "finding",
            "finding_title",
            "scan_run_id",
            "organization",
            "explanation",
            "remediation",
            "code_example",
            "risk_score",
            "priority",
            "model_name",
            "source",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class AiAnalyzeSerializer(serializers.Serializer):
    finding = serializers.PrimaryKeyRelatedField(queryset=ScanFinding.objects.all(), required=False, allow_null=True)
    scan_run = serializers.PrimaryKeyRelatedField(queryset=ScanRun.objects.all(), required=False, allow_null=True)

    def validate(self, attrs):
        finding = attrs.get("finding")
        scan_run = attrs.get("scan_run")
        if finding is None and scan_run is None:
            raise serializers.ValidationError("Provide a finding or a scan run.")
        if finding is not None and scan_run is not None:
            raise serializers.ValidationError("Provide only one of finding or scan run.")
        request = self.context.get("request")
        organization = getattr(request, "current_organization", None) if request else None
        if organization is not None:
            if finding is not None and finding.scan_run.organization_id != organization.id:
                raise serializers.ValidationError("The finding is outside the active organization.")
            if scan_run is not None and scan_run.organization_id != organization.id:
                raise serializers.ValidationError("The scan is outside the active organization.")
        return attrs
