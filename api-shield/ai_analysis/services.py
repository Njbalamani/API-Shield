import logging

import requests
from django.conf import settings

from .models import AiAnalysis

logger = logging.getLogger("apishield")

SEVERITY_SCORES = {
    "info": 10.0,
    "low": 30.0,
    "medium": 55.0,
    "high": 78.0,
    "critical": 95.0,
}

CONFIDENCE_MULTIPLIERS = {
    "low": 0.7,
    "medium": 0.85,
    "high": 1.0,
}

RISK_TERMS = (
    "unauthenticated",
    "administrator",
    "password",
    "token",
    "sql",
    "cross-site",
    "exposure",
)

GUIDANCE = {
    "bola": {
        "explanation": (
            "The endpoint uses an object identifier without documented proof that the authenticated "
            "principal owns the object. This is a BOLA indicator and needs object-level authorization checks."
        ),
        "remediation": (
            "Resolve every requested object through the current user's authorization scope, deny "
            "inaccessible identifiers, and add automated tests for cross-user access."
        ),
        "code_example": (
            "from django.shortcuts import get_object_or_404\n"
            "from rest_framework.permissions import IsAuthenticated\n"
            "from rest_framework.views import APIView\n\n"
            "class OrderDetailView(APIView):\n"
            "    permission_classes = [IsAuthenticated]\n\n"
            "    def get(self, request, order_id):\n"
            "        order = get_object_or_404(request.user.orders.all(), pk=order_id)\n"
            "        return Response(OrderSerializer(order).data)\n"
        ),
    },
    "bfla": {
        "explanation": (
            "A state-changing operation does not document role or scope enforcement. This is a BFLA "
            "indicator because privileged functions may be reachable by lower-privilege users."
        ),
        "remediation": (
            "Map every write operation to a required role or scope, deny by default, and verify the "
            "privilege boundary with integration tests."
        ),
        "code_example": (
            "from rest_framework.decorators import action\n"
            "from rest_framework.permissions import IsAdminUser\n"
            "from rest_framework.response import Response\n"
            "from rest_framework.viewsets import ModelViewSet\n\n"
            "class SettingsViewSet(ModelViewSet):\n"
            "    @action(detail=False, methods=['put'], permission_classes=[IsAdminUser])\n"
            "    def admin_update(self, request):\n"
            "        serializer = self.get_serializer(data=request.data)\n"
            "        serializer.is_valid(raise_exception=True)\n"
            "        serializer.save()\n"
            "        return Response(serializer.data)\n"
        ),
    },
    "auth": {
        "explanation": (
            "Authentication metadata is missing or incomplete. Missing schemes, weak token lifetime "
            "guidance, or credentials in URLs can allow account takeover or credential leakage."
        ),
        "remediation": (
            "Require authentication on protected operations, document the scheme, enforce short token "
            "lifetimes, and transmit credentials only over TLS in headers or secure cookies."
        ),
        "code_example": (
            "SIMPLE_JWT = {\n"
            "    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),\n"
            "    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),\n"
            "    'ROTATE_REFRESH_TOKENS': True,\n"
            "    'BLACKLIST_AFTER_ROTATION': True,\n"
            "}\n"
        ),
    },
    "sqli": {
        "explanation": (
            "Parameter names suggest values may be concatenated into SQL statements. Attacker-controlled "
            "query fragments can alter statement structure."
        ),
        "remediation": (
            "Use parameterized queries, validate sort and filter names against strict allowlists, and run "
            "the application with least-privilege database credentials."
        ),
        "code_example": (
            "from django.db.models import Q\n\n"
            "ALLOWED_SORT_FIELDS = {'created_at', 'name'}\n\n"
            "def list_records(request):\n"
            "    sort = request.query_params.get('sort', 'created_at')\n"
            "    if sort not in ALLOWED_SORT_FIELDS:\n"
            "        raise ValidationError('Unsupported sort field')\n"
            "    return Record.objects.filter(owner=request.user).order_by(sort)\n"
        ),
    },
    "xss": {
        "explanation": (
            "Reflected or stored values may be rendered as markup. Without contextual output encoding, an "
            "attacker can execute script in another user's browser."
        ),
        "remediation": (
            "Apply context-aware encoding on output, validate accepted characters, set a restrictive "
            "Content Security Policy, and avoid reflecting raw values."
        ),
        "code_example": (
            "from django.utils.html import escape\n"
            "from django.http import JsonResponse\n\n"
            "def comment_view(request):\n"
            "    body = escape(request.POST.get('body', ''))\n"
            "    return JsonResponse({'body': body})\n"
        ),
    },
    "misconfig": {
        "explanation": (
            "Configuration or documentation gaps increase attack surface and make security controls "
            "difficult to verify."
        ),
        "remediation": (
            "Enforce TLS, remove unnecessary methods, set defensive response headers, and keep OpenAPI "
            "descriptions and security schemes complete."
        ),
        "code_example": (
            "SECURE_BROWSER_XSS_FILTER = True\n"
            "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
            "X_FRAME_OPTIONS = 'DENY'\n"
            "SECURE_HSTS_SECONDS = 31536000\n"
            "SESSION_COOKIE_SECURE = True\n"
        ),
    },
    "ratelimit": {
        "explanation": (
            "Sensitive or expensive operations without throttling can be abused for credential stuffing, "
            "scraping, or denial of service."
        ),
        "remediation": (
            "Apply per-principal and per-IP rate limits, bound page sizes, and return 429 responses with "
            "Retry-After headers."
        ),
        "code_example": (
            "from rest_framework.throttling import ScopedRateThrottle\n"
            "from rest_framework.views import APIView\n\n"
            "class LoginView(APIView):\n"
            "    throttle_scope = 'authentication'\n"
            "    throttle_classes = [ScopedRateThrottle]\n"
        ),
    },
    "data": {
        "explanation": (
            "Responses or contracts include fields associated with sensitive data. Excessive exposure can "
            "reveal information beyond the caller's need."
        ),
        "remediation": (
            "Return only fields required by the client, mask sensitive values, and apply field-level "
            "authorization before serialization."
        ),
        "code_example": (
            "from rest_framework import serializers\n\n"
            "class InvoiceSerializer(serializers.ModelSerializer):\n"
            "    email = serializers.SerializerMethodField()\n\n"
            "    class Meta:\n"
            "        model = Invoice\n"
            "        fields = ['id', 'total', 'email']\n\n"
            "    def get_email(self, obj):\n"
            "        return obj.owner.email if self.context['request'].user.is_staff else '[REDACTED]'\n"
        ),
    },
    "validation": {
        "explanation": (
            "Missing schema constraints allow unexpected values, oversized payloads, or undeclared "
            "properties to reach application logic."
        ),
        "remediation": (
            "Validate every request against an explicit schema, reject unknown properties, and define "
            "type, length, and range constraints."
        ),
        "code_example": (
            "from rest_framework import serializers\n\n"
            "class SearchSerializer(serializers.Serializer):\n"
            "    query = serializers.CharField(max_length=200, required=True)\n"
            "    limit = serializers.IntegerField(min_value=1, max_value=100, default=20)\n\n"
            "    def validate_query(self, value):\n"
            "        if not value.strip():\n"
            "            raise serializers.ValidationError('Query cannot be blank')\n"
            "        return value.strip()\n"
        ),
    },
    "default": {
        "explanation": (
            "APIShield identified a security indicator that requires review in the context of the affected operation."
        ),
        "remediation": (
            "Review the evidence, confirm whether the behavior is intentional, and apply the applicable "
            "framework-level control."
        ),
        "code_example": (
            "from rest_framework.permissions import IsAuthenticated\n"
            "from rest_framework.views import APIView\n\n"
            "class SecuredView(APIView):\n"
            "    permission_classes = [IsAuthenticated]\n"
        ),
    },
}


def guidance_for(finding):
    haystack = " ".join(
        [
            str(finding.owasp_category or "").lower(),
            str(finding.title or "").lower(),
            str(finding.description or "").lower(),
        ]
    )
    rules = (
        ("bfla", ("bfla", "function level")),
        ("bola", ("bola", "object level", "ownership")),
        ("auth", ("authentication", "jwt", "oauth", "token handling", "expiration")),
        ("sqli", ("sql", "injection")),
        ("xss", ("xss", "cross-site", "markup", "reflected")),
        ("ratelimit", ("rate", "resource consumption")),
        ("data", ("exposure", "sensitive data", "data field")),
        ("validation", ("validation", "input constraint")),
        ("misconfig", ("misconfiguration", "configuration", "security header")),
    )
    for key, terms in rules:
        if any(term in haystack for term in terms):
            return GUIDANCE[key]
    return GUIDANCE["default"]


def keyword_count(finding):
    text = f"{finding.title or ''} {finding.description or ''}".lower()
    return min(6, sum(1 for term in RISK_TERMS if term in text))


def deterministic_score_from_features(severity_index, confidence_index, verified, terms):
    base = list(SEVERITY_SCORES.values())[severity_index]
    multiplier = list(CONFIDENCE_MULTIPLIERS.values())[confidence_index]
    score = base * multiplier + 8.0 * verified + 3.0 * terms
    return round(max(0.0, min(100.0, score)), 2)


def deterministic_local_score(finding):
    severity = str(finding.severity or "medium").lower()
    confidence = str(finding.confidence or "medium").lower()
    severity_index = list(SEVERITY_SCORES).index(severity) if severity in SEVERITY_SCORES else 2
    confidence_index = list(CONFIDENCE_MULTIPLIERS).index(confidence) if confidence in CONFIDENCE_MULTIPLIERS else 1
    return deterministic_score_from_features(
        severity_index, confidence_index, int(bool(finding.verified)), keyword_count(finding)
    )


def local_risk_score(finding):
    fallback = deterministic_local_score(finding)
    try:
        import numpy as np
        from sklearn.linear_model import LinearRegression
    except Exception:
        return fallback, "local-risk-model"
    features = []
    targets = []
    for severity_index in range(len(SEVERITY_SCORES)):
        for confidence_index in range(len(CONFIDENCE_MULTIPLIERS)):
            for verified in (0, 1):
                for terms in range(7):
                    features.append([severity_index, confidence_index, verified, terms])
                    targets.append(deterministic_score_from_features(severity_index, confidence_index, verified, terms))
    try:
        model = LinearRegression().fit(np.asarray(features, dtype=float), np.asarray(targets, dtype=float))
        severity = str(finding.severity or "medium").lower()
        confidence = str(finding.confidence or "medium").lower()
        severity_index = list(SEVERITY_SCORES).index(severity) if severity in SEVERITY_SCORES else 2
        confidence_index = list(CONFIDENCE_MULTIPLIERS).index(confidence) if confidence in CONFIDENCE_MULTIPLIERS else 1
        feature_vector = [[severity_index, confidence_index, int(bool(finding.verified)), keyword_count(finding)]]
        vector = np.asarray(feature_vector, dtype=float)
        predicted = float(model.predict(vector)[0])
        if not 0.0 <= predicted <= 100.0:
            return fallback, "local-risk-model"
        score = round(0.7 * fallback + 0.3 * predicted, 2)
        return score, "local-risk-model-sklearn"
    except Exception:
        return fallback, "local-risk-model"


def priority_for(score):
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def parse_gemini_text(text, fallback):
    explanation = None
    remediation = None
    code_example = None
    current = None
    for line in str(text).splitlines():
        marker = line.strip().upper()
        if marker in {"[EXPLANATION]", "EXPLANATION:"}:
            current = "explanation"
            continue
        if marker in {"[REMEDIATION]", "REMEDIATION:"}:
            current = "remediation"
            continue
        if marker in {"[CODE]", "CODE:"}:
            current = "code"
            continue
        if not line.strip():
            continue
        if current == "explanation":
            explanation = f"{explanation or ''} {line.strip()}".strip()
        elif current == "remediation":
            remediation = f"{remediation or ''} {line.strip()}".strip()
        elif current == "code":
            code_example = f"{code_example or ''}\n{line}".strip()
    return {
        "explanation": explanation or fallback["explanation"],
        "remediation": remediation or fallback["remediation"],
        "code_example": code_example or fallback["code_example"],
    }


def gemini_enhancement(finding, guidance):
    config = settings.APISHIELD
    if not config.get("AI_EXPLANATIONS_ENABLED"):
        return None
    api_key = str(config.get("GEMINI_API_KEY") or "").strip()
    if not api_key:
        return None
    model = str(config.get("GEMINI_MODEL") or "gemini-1.5-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    prompt = (
        "Review this API security finding and provide concise guidance.\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity}\n"
        f"Category: {finding.owasp_category}\n"
        f"Description: {finding.description}\n"
        "Respond with [EXPLANATION], [REMEDIATION], and [CODE] sections. Do not include credentials."
    )
    try:
        response = requests.post(
            url,
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 700},
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning("Gemini request failed with %s", type(exc).__name__)
        return None
    if response.status_code != 200:
        logger.warning("Gemini request returned status %s", response.status_code)
        return None
    try:
        payload = response.json()
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
    except (ValueError, KeyError, IndexError, TypeError):
        logger.warning("Gemini response was malformed")
        return None
    return parse_gemini_text(text, guidance)


def analyze_finding(finding):
    score, model_name = local_risk_score(finding)
    guidance = guidance_for(finding)
    explanation = f"{guidance['explanation']} Affected operation: {finding.title}."
    remediation = guidance["remediation"]
    code_example = guidance["code_example"]
    source = AiAnalysis.Source.LOCAL
    enhancement = gemini_enhancement(finding, guidance)
    if enhancement:
        explanation = enhancement["explanation"]
        remediation = enhancement["remediation"]
        code_example = enhancement["code_example"]
        source = AiAnalysis.Source.HYBRID
        model_name = str(settings.APISHIELD.get("GEMINI_MODEL") or "gemini")
    analysis, _ = AiAnalysis.objects.update_or_create(
        finding=finding,
        defaults={
            "organization": finding.scan_run.organization,
            "explanation": explanation,
            "remediation": remediation,
            "code_example": code_example,
            "risk_score": score,
            "priority": priority_for(score),
            "model_name": model_name,
            "source": source,
        },
    )
    return analysis


def analyze_scan(scan_run):
    analyses = [analyze_finding(finding) for finding in scan_run.findings.select_related("scan_run").all()]
    return {
        "scan_run_id": scan_run.id,
        "analyzed": len(analyses),
        "analyses": analyses,
    }
