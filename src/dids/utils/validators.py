from importlib import resources
import jsonschema
import json

from django.utils import timezone

from ninja.errors import HttpError

from src.core.ratelimit import enforce_min_interval
from src.auditaction.models import AuditAction, AuditCategory
from src.auditaction.services import audit_action_create
from src.users.services import user_verify_email_otp

def _audit(user, action: AuditAction, msg: str, details: dict | None) -> None:
    audit_action_create(
        user=user,
        action=action,
        category=AuditCategory.DID,
        details={"message": msg, **(details or {})},
    )

def validate_did_document(doc: dict):
    with resources.files("src.dids.schemas").joinpath("did_document.schema.json").open("rb") as f:
        schema = json.load(f)
    jsonschema.validate(instance=doc, schema=schema)
    
def verify_or_raise(user, otp_code: str | None, *, scope: str) -> None:
    """
    Verify a one-time code for a sensitive action.
    scope: one of {"publish", "deactivate"} to key rate-limits/audit.
    """
    
    # Mild anti-briteforce: 1 attempt / 10 seconds per scope
    enforce_min_interval(user=user, key=f"otp:{scope}", min_seconds=10)
    
    if not otp_code or not isinstance(otp_code, str) or not otp_code.strip():
            _audit(user, AuditAction.OTP_REQUIRED, "OTP required", {"scope": scope})
            raise HttpError(400, "OTP_REQUIRED")

    ok = False
    try:
        ok = bool(user_verify_email_otp(user=user, code=otp_code.strip()))
    except Exception as exc:
        # Keep service errors opaque to caller; treat as invalid
        _audit(user, AuditAction.OTP_ERROR, "OTP service error", {"scope": scope, "error": str(exc)})
        raise HttpError(401, "OTP_INVALID")

    if not ok:
        _audit(user, AuditAction.OTP_FAILED, "OTP verification failed", {"scope": scope})
        raise HttpError(401, "OTP_INVALID")

    _audit(user, AuditAction.OTP_VERIFIED, "OTP verification success", {"scope": scope, "ts": timezone.now().isoformat()})