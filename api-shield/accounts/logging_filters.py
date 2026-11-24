import logging

from .middleware import REQUEST_ID_VAR


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = REQUEST_ID_VAR.get()
        return True
