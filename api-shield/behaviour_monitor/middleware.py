import ipaddress
import logging
import time

from api_projects.models import ApiProject
from endpoint_discovery.models import ApiEndpoint

from .services import analyse_request_log, record_request

logger = logging.getLogger("apishield")

API_PATH_PREFIXES = ("/api/", "/oauth/token/")


class ApiBehaviourMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not self._is_api_path(getattr(request, "path", "")):
            return self.get_response(request)
        context = self._safe_context(request)
        started = time.monotonic()
        try:
            response = self.get_response(request)
        except Exception:
            self._safe_record(request, context, None, started)
            raise
        self._safe_record(request, context, getattr(response, "status_code", None), started)
        return response

    def _is_api_path(self, path):
        return path == "/api" or any(path.startswith(prefix) for prefix in API_PATH_PREFIXES)

    def _safe_context(self, request):
        try:
            organization = getattr(request, "current_organization", None)
            if organization is None:
                return None
            project = self._resolve_project(request, organization)
            if project is None:
                return None
            endpoint = self._resolve_endpoint(request, organization, project)
            return organization, project, endpoint
        except Exception:
            logger.debug("behaviour monitor context resolution skipped", exc_info=True)
            return None

    def _resolve_project(self, request, organization):
        project_id = request.headers.get("X-Project-ID", "")
        if project_id.isdigit():
            project = ApiProject.objects.filter(
                id=int(project_id),
                organization=organization,
                status=ApiProject.Status.ACTIVE,
            ).first()
            if project is not None:
                return project
        return (
            ApiProject.objects.filter(organization=organization, status=ApiProject.Status.ACTIVE)
            .order_by("name")
            .first()
        )

    def _resolve_endpoint(self, request, organization, project):
        endpoint_id = request.headers.get("X-Endpoint-ID", "")
        if not endpoint_id.isdigit():
            return None
        return ApiEndpoint.objects.filter(id=int(endpoint_id), project__organization=organization).first()

    def _safe_record(self, request, context, status_code, started):
        if context is None:
            return
        organization, project, endpoint = context
        try:
            raw_ip = request.META.get("REMOTE_ADDR") or None
            ip_address = None
            if raw_ip:
                ip_address = str(ipaddress.ip_address(raw_ip))
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log = record_request(
                organization=organization,
                project=project,
                endpoint=endpoint,
                method=request.method,
                path=request.path,
                ip_address=ip_address,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                status_code=status_code,
                response_time_ms=elapsed_ms,
                query_keys=list(request.GET.keys()),
            )
            analyse_request_log(log)
        except Exception:
            logger.debug("behaviour monitor recording skipped", exc_info=True)
