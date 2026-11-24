from rest_framework import serializers


class SeverityCountSerializer(serializers.Serializer):
    severity = serializers.CharField()
    count = serializers.IntegerField()


class OWASPCountSerializer(serializers.Serializer):
    owasp_category = serializers.CharField()
    count = serializers.IntegerField()


class RecentScanSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    project__name = serializers.CharField()
    status = serializers.CharField()
    mode = serializers.CharField()
    risk_score = serializers.FloatField()
    findings_count = serializers.IntegerField()
    critical_count = serializers.IntegerField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)


class TrendPointSerializer(serializers.Serializer):
    date = serializers.CharField()
    scans = serializers.IntegerField()
    findings = serializers.IntegerField()


class MetricsSerializer(serializers.Serializer):
    total_endpoints = serializers.IntegerField()
    active_endpoints = serializers.IntegerField()
    total_projects = serializers.IntegerField()
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    open_vulnerabilities = serializers.IntegerField()
    critical_findings = serializers.IntegerField()
    high_findings = serializers.IntegerField()
    verified_findings = serializers.IntegerField()
    api_risk_score = serializers.FloatField()
    severity_distribution = SeverityCountSerializer(many=True)
    owasp_category_distribution = OWASPCountSerializer(many=True)
    recent_scans = RecentScanSerializer(many=True)
    trend = TrendPointSerializer(many=True)
    trend_days = serializers.IntegerField()
    alert_count = serializers.IntegerField()
    open_alert_count = serializers.IntegerField()
    acknowledged_alert_count = serializers.IntegerField()
    resolved_alert_count = serializers.IntegerField()
    authentication_score = serializers.FloatField()
    failed_authentication_checks = serializers.IntegerField()
    warning_authentication_checks = serializers.IntegerField()


class TopologyNodeSerializer(serializers.Serializer):
    id = serializers.CharField()
    label = serializers.CharField()
    type = serializers.CharField()
    metadata = serializers.JSONField()


class TopologyLinkSerializer(serializers.Serializer):
    source = serializers.CharField()
    target = serializers.CharField()
    type = serializers.CharField()
    method = serializers.CharField()


class TopologySerializer(serializers.Serializer):
    nodes = TopologyNodeSerializer(many=True)
    links = TopologyLinkSerializer(many=True)
