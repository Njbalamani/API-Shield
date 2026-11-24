import contextvars
import uuid

REQUEST_ID_VAR = contextvars.ContextVar("request_id", default="-")


class RequestIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.request_id = request_id
        token = REQUEST_ID_VAR.set(request_id)
        try:
            response = self.get_response(request)
        finally:
            REQUEST_ID_VAR.reset(token)
        response["X-Request-ID"] = request_id
        return response
