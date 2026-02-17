from __future__ import annotations

import uuid
from typing import Any

from django.db import transaction
from django.http import HttpRequest

from src.auditaction.models import AuditLog, AuditCategory, Severity


def _infer_category_from_action(action: str) -> str:
    """
    If not provided, infer category from the action's prefix (e.g., ORGANIZATION_CREATED).
    Falls back to SYSTEM when unknown.
    """
    if not action:
        return AuditCategory.SYSTEM
    prefix = action.split("_", 1)[0].upper()
    if prefix in AuditCategory.values:
        return prefix
    return AuditCategory.SYSTEM


def _extract_request_meta(request: HttpRequest | None) -> tuple[str | None, str, str]:
    if not request:
        return None, "", ""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    ip = (xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")) or None
    ua = request.META.get("HTTP_USER_AGENT", "")
    req_id = (
        request.headers.get("X-Request-Id")
        or request.META.get("HTTP_X_REQUEST_ID")
        or getattr(request, "id", "")  # some middleware attach a UUID here
        or ""
    )
    # Coerce UUID to str if needed
    if isinstance(req_id, uuid.UUID):
        req_id = str(req_id)
    return ip, ua, str(req_id)


def _json_sanitize(obj: Any) -> Any:
    # Primitives
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    # UUID → str
    if isinstance(obj, uuid.UUID):
        return str(obj)
    # Datetime/date/time → ISO
    if hasattr(obj, "isoformat"):
        try:
            return obj.isoformat()
        except Exception:
            pass
    # Dict → recurse
    if isinstance(obj, dict):
        return {str(_json_sanitize(k)): _json_sanitize(v) for k, v in obj.items()}
    # List/tuple/set → list recurse
    if isinstance(obj, (list, tuple, set)):
        return [_json_sanitize(v) for v in obj]
    # Django model instance → pk
    if hasattr(obj, "pk"):
        return obj.pk
    # Fallback
    return str(obj)


@transaction.atomic
def audit_action_create(
    *,
    user,
    action: str,
    details: dict[str, any] | None = None,
    category: str | None = None,
    organization=None,
    target_type: str = "",
    target_id: str | None = None,
    severity: str = Severity.INFO,
    request: HttpRequest | None = None,
) -> AuditLog:
    """
    Create a single audit entry. Safe to call from anywhere.
    - If category is None, inferred from action prefix.
    - If organization is None and user has organization, it will be attached.
    - If request is provided, IP, UA and request_id are captured.
    """
    resolved_category = category or _infer_category_from_action(action)
    resolved_org = organization or (
        getattr(user, "organization", None) if user else None
    )
    ip, ua, req_id = _extract_request_meta(request)
    details = _json_sanitize(details or {})
    entry = AuditLog.objects.create(
        user=user if getattr(user, "pk", None) else None,
        organization=resolved_org,
        category=resolved_category,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        severity=severity,
        ip_address=ip,
        user_agent=ua,
        request_id=req_id or "",
    )
    return entry
