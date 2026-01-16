from typing import Any
from django.http import JsonResponse
from django.utils.timezone import now

def _extract_request_id(request) -> str:
    return request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID") or uuid4().hex[:8]


def registrar_ok(request,
                 did_state: dict[str, Any],
                 did_reg_meta: dict[str, Any] | None = None,
                 did_doc_meta: dict[str, Any] | None = None,
                 status: int = 200):
    meta = dict(did_reg_meta or {})
    meta.setdefault("method", "web")
    meta["requestId"] = _extract_request_id(request)
    body = {
        "didState": did_state,
        "didRegistrationMetadata": meta,
        "didDocumentMetadata": did_doc_meta or {},
    }
    return JsonResponse(body, status=status)


def registrar_err(status_code: int, message: str, path: str, request_id: str = ""):
    return JsonResponse({
        "timestamp": int(now().timestamp() * 1000),
        "path": path,
        "status": status_code,
        "error": "Error",
        "requestId": request_id,
        "message": message,
        "didState": {"state": "error", "message": message},
    }, status=status_code)
