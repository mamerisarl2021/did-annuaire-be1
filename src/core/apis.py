from __future__ import annotations
from typing import Any

from ninja_extra.controllers import ControllerBase


class BaseAPIController(ControllerBase):
    def create_response(self, *, message: str = "", data: Any = None, extra: dict[str, Any] | None = None,
                        errors: Any = None, status_code: int = 200, code: str | None = None,):

        request = getattr(self, "context", None) and getattr(self.context, "request", None)
        request_id = ""
        if request:

            request_id = request.headers.get("X-Request-Id", "") or request.META.get("HTTP_X_REQUEST_ID", "") or ""

        payload = {"success": 200 <= status_code < 400,
                   "message": message,
                   "data": data if data is not None else {},
                   "extra": extra or {},
                   "errors": errors,
                   "code": code,
                   "request_id": request_id,
                   }
        return super().create_response(payload, status_code=status_code)
