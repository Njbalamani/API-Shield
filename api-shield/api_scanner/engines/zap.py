import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from django.conf import settings

from .base import BaseScanEngine, RuleMixin, ScanFindingData, normalize_confidence, sanitize_text

ZAP_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}

ZAP_CONFIDENCE = {
    "0": "low",
    "1": "low",
    "2": "medium",
    "3": "medium",
}

SENSITIVE_QUERY_TERMS = ("token", "password", "secret", "api_key", "apikey", "authorization", "session")


def sanitized_url(value):
    try:
        parsed = urlparse(str(value or ""))
    except ValueError:
        return "[INVALID_URL]"
    query = [
        (key, "[REDACTED]" if any(term in key.lower() for term in SENSITIVE_QUERY_TERMS) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(query), ""))


class ZapEngine(RuleMixin, BaseScanEngine):
    name = "zap"

    def scan(self):
        config = settings.APISHIELD
        if not config.get("ALLOW_ZAP"):
            self.log("WARNING", "ZAP integration disabled by configuration", {"reason": "allow_zap_false"})
            return []
        api_url = str(config.get("ZAP_API_URL") or "").strip()
        if not api_url:
            self.log("WARNING", "ZAP integration disabled by configuration", {"reason": "api_url_missing"})
            return []
        policy = getattr(self.project, "scan_policy", None)
        if policy is not None and not policy.allow_zap:
            self.log("WARNING", "ZAP integration disabled by project policy", {"reason": "policy_allow_zap_false"})
            return []

        client = self.build_client(api_url, str(config.get("ZAP_API_KEY") or ""))
        if client is None:
            return []
        host_context = {"zap_host": urlparse(api_url).hostname or ""}
        try:
            version = client.core.version()
        except Exception as exc:
            self.log("WARNING", "ZAP unavailable", {**host_context, "exception": type(exc).__name__})
            return []

        target = str(self.project.base_url or "").strip()
        if not target:
            self.log("WARNING", "ZAP scan skipped because the project has no base URL", host_context)
            return []
        self.log("INFO", "ZAP integration connected", {**host_context, "version": sanitize_text(version)[:80]})
        self.run_spider(client, target, host_context)
        if self.scan_run.authorization_verified:
            self.run_active_scan(client, target, host_context)
        return self.collect_alerts(client, target, host_context)

    def build_client(self, api_url, api_key):
        try:
            import zapv2
        except Exception as exc:
            self.log("WARNING", "ZAP integration unavailable", {"exception": type(exc).__name__})
            return None
        proxies = {"http": api_url, "https": api_url}
        try:
            return zapv2.ZAPv2(apikey=api_key, proxies=proxies)
        except TypeError:
            try:
                return zapv2.ZAPv2(apikey=api_key, address=api_url)
            except Exception as exc:
                self.log("WARNING", "ZAP client initialization failed", {"exception": type(exc).__name__})
                return None
        except Exception as exc:
            self.log("WARNING", "ZAP client initialization failed", {"exception": type(exc).__name__})
            return None

    def wait_for_completion(self, status_call, target, timeout):
        deadline = time.monotonic() + max(1, min(timeout, 120))
        while time.monotonic() < deadline:
            try:
                progress = str(status_call(target))
            except Exception as exc:
                self.log("WARNING", "ZAP status check failed", {"exception": type(exc).__name__})
                return False
            if progress.isdigit() and int(progress) >= 100:
                return True
            time.sleep(1)
        return False

    def run_spider(self, client, target, host_context):
        spider = getattr(client, "spider", None)
        if spider is None:
            return
        try:
            scan_id = spider.scan(target=target, maxchildren=10)
        except Exception as exc:
            self.log("WARNING", "ZAP spider could not start", {**host_context, "exception": type(exc).__name__})
            return
        completed = self.wait_for_completion(spider.status, str(scan_id), 30)
        self.log("INFO", "ZAP spider finished", {**host_context, "completed": completed})

    def run_active_scan(self, client, target, host_context):
        active = getattr(client, "ascan", None)
        if active is None:
            return
        try:
            scan_id = active.scan(target=target)
        except Exception as exc:
            self.log("WARNING", "ZAP active scan could not start", {**host_context, "exception": type(exc).__name__})
            return
        completed = self.wait_for_completion(active.status, str(scan_id), 90)
        self.log("INFO", "ZAP active scan finished", {**host_context, "completed": completed})

    def collect_alerts(self, client, target, host_context):
        try:
            alerts = client.core.alerts(baseurl=target)
        except Exception as exc:
            self.log("WARNING", "ZAP alerts unavailable", {**host_context, "exception": type(exc).__name__})
            return []
        if not isinstance(alerts, list):
            return []
        findings = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            values = self.rule_values("ZAP-ALERT-015")
            severity = ZAP_SEVERITY.get(str(alert.get("risk", "1")), "low")
            confidence = normalize_confidence(ZAP_CONFIDENCE.get(str(alert.get("confidence", "1")), "low"))
            evidence = {
                "alert_id": sanitize_text(alert.get("id", ""))[:80],
                "name": sanitize_text(alert.get("name", "ZAP alert"))[:200],
                "url": sanitized_url(alert.get("url", "")),
                "parameter": sanitize_text(alert.get("param", ""))[:120],
            }
            findings.append(
                ScanFindingData(
                    title=str(alert.get("name") or values["title"])[:240],
                    description=sanitize_text(alert.get("description") or values["description"]),
                    severity=severity,
                    confidence=confidence,
                    owasp_category=values["owasp_category"],
                    cwe=values["cwe"],
                    rule_id="ZAP-ALERT-015",
                    evidence=evidence,
                    response={"detail": sanitize_text(alert.get("detail", ""))[:1000]},
                    remediation=values["remediation"],
                    verified=False,
                )
            )
        self.log("INFO", "ZAP alerts converted", {**host_context, "finding_count": len(findings)})
        return findings
