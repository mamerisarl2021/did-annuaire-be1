from typing import Any
from uuid import uuid4
from django.http import JsonResponse
from django.utils.timezone import now


def _req_id(request) -> str:
    return (
        request.headers.get("X-Request-Id")
        or request.headers.get("X-Request-ID")
        or uuid4().hex[:8]
    )


def ok(
    request,
    did_state: dict[str, Any],
    did_reg_meta: dict[str, Any] | None = None,
    did_doc_meta: dict[str, Any] | None = None,
    status: int = 200,
) -> JsonResponse:
    meta = dict(did_reg_meta or {})
    meta.setdefault("method", "web")
    meta["requestId"] = _req_id(request)
    return JsonResponse(
        {
            "didState": did_state,
            "didRegistrationMetadata": meta,
            "didDocumentMetadata": did_doc_meta or {},
        },
        status=status,
    )


def err(request, status_code: int, message: str, path: str = "") -> JsonResponse:
    rid = _req_id(request)
    return JsonResponse(
        {
            "timestamp": int(now().timestamp() * 1000),
            "path": path,
            "status": status_code,
            "error": "Error",
            "requestId": rid,
            "message": message,
            "didState": {"state": "error", "message": message},
        },
        status=status_code,
    )
