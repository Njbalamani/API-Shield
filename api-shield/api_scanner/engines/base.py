import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SEVERITY_WEIGHTS = {
    "info": 5.0,
    "low": 20.0,
    "medium": 45.0,
    "high": 75.0,
    "critical": 95.0,
}

CONFIDENCE_MULTIPLIERS = {
    "low": 0.6,
    "medium": 0.8,
    "high": 1.0,
}

SENSITIVE_KEY_TERMS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "credential",
)

REDACTION_PATTERNS = (
    re.compile(
        r"(?i)(authorization|api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|token|password|secret)"
        r"\s*[:=]\s*[^\s&\"']+"
    ),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~-]+"),
)


def normalize_severity(value: Any) -> str:
    normalized = str(value or "medium").lower()
    return normalized if normalized in SEVERITY_WEIGHTS else "medium"


def normalize_confidence(value: Any, allowed: tuple[str, ...] | None = None) -> str:
    normalized = str(value or "medium").lower()
    if normalized not in CONFIDENCE_MULTIPLIERS:
        normalized = "medium"
    if allowed and normalized not in allowed:
        return allowed[0]
    return normalized


def compute_risk_score(severity: Any, confidence: Any = "medium", verified: bool = False) -> float:
    base = SEVERITY_WEIGHTS[normalize_severity(severity)]
    multiplier = CONFIDENCE_MULTIPLIERS[normalize_confidence(confidence)]
    score = base * multiplier
    if verified:
        score *= 1.15
    return round(min(score, 100.0), 2)


def sanitize_text(value: Any) -> str:
    text = str(value)
    for pattern in REDACTION_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]" if match.lastindex else "[REDACTED]", text)
    return text[:2000]


def sanitize_mapping(value: Any, key: str | None = None) -> Any:
    if key is not None and any(term in str(key).lower().replace("-", "_") for term in SENSITIVE_KEY_TERMS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): sanitize_mapping(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_mapping(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


@dataclass
class ScanFindingData:
    title: str
    description: str
    severity: str = "medium"
    confidence: str = "medium"
    owasp_category: str = ""
    cwe: str = ""
    endpoint: Any = None
    rule_id: str = ""
    evidence: dict = field(default_factory=dict)
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    remediation: dict = field(default_factory=dict)
    verified: bool = False
    risk_score: float = 0.0

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        self.confidence = normalize_confidence(self.confidence)
        self.evidence = sanitize_mapping(self.evidence or {})
        self.request = sanitize_mapping(self.request or {})
        self.response = sanitize_mapping(self.response or {})
        self.remediation = sanitize_mapping(self.remediation or {})
        self.verified = bool(self.verified)
        if not self.risk_score:
            self.risk_score = compute_risk_score(self.severity, self.confidence, self.verified)


LogCallback = Callable[[str, str, dict | None], None]


class BaseScanEngine(ABC):
    name = "base"

    def __init__(self, scan_run, log: LogCallback | None = None):
        self.scan_run = scan_run
        self.project = scan_run.project
        self.log_callback = log

    def log(self, level: str, message: str, context: dict | None = None):
        if self.log_callback is not None:
            self.log_callback(level, message, sanitize_mapping(context or {}))

    @abstractmethod
    def scan(self) -> list[ScanFindingData]:
        raise NotImplementedError


class RuleMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rules = None

    def rules(self):
        if self._rules is None:
            from api_scanner.models import ScanRule

            self._rules = {rule.rule_id: rule for rule in ScanRule.objects.filter(enabled=True)}
        return self._rules

    def rule_values(self, rule_id, **overrides):
        rule = self.rules().get(rule_id)
        values = {
            "title": rule.title if rule else rule_id,
            "description": rule.description if rule else "APIShield heuristic finding.",
            "severity": rule.severity if rule else "medium",
            "confidence": rule.confidence if rule else "medium",
            "owasp_category": rule.owasp_category if rule else "",
            "cwe": rule.cwe if rule else "",
            "remediation": dict(rule.remediation or {}) if rule else {},
        }
        values.update(overrides)
        return values
