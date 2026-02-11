import traceback

from django.conf import settings
from ninja_extra import NinjaExtraAPI
from ninja.errors import ValidationError as NinjaValidationError
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError

# psycopg 3: use error classes under psycopg.errors (no "errorcodes" module)
from psycopg import errors as pg_errors

from src.core.exceptions import APIError


def attach_exception_handlers(api: NinjaExtraAPI) -> None:
    def _envelope(request, *, message: str, status: int, code: str, data=None, errors=None, extra=None,):
        return api.create_response(
            request,
            {
                "success": 200 <= status < 400,
                "message": message,
                "data": data or {},
                "extra": extra or {},
                "errors": errors,
                "code": code,
                "request_id": request.headers.get("X-Request-Id", "")
                or request.META.get("HTTP_X_REQUEST_ID", "")
                or "",
            },
            status=status,
        )

    @api.exception_handler(APIError)
    def on_api_error(request, exc: APIError):
        return _envelope(
            request,
            message=exc.message,
            status=exc.status,
            code=exc.code,
            errors=exc.errors,
            extra=exc.extra,
        )

    @api.exception_handler(IntegrityError)
    def on_integrity_error(request, exc: IntegrityError):
        # Default
        status, code, msg, field = 409, "CONFLICT", "Conflict", None

        cause = getattr(exc, "__cause__", None)
        # psycopg 3 diagnostics (may be None depending on backend/driver)
        diag = getattr(cause, "diag", None) if cause else None
        constraint = getattr(diag, "constraint_name", "") if diag else ""
        pgcode = getattr(cause, "pgcode", "") or getattr(diag, "sqlstate", "") or ""

        # Unique violation detection:
        is_unique = isinstance(cause, pg_errors.UniqueViolation) if cause else False
        if not is_unique:
            is_unique = pgcode == "23505"  # SQLSTATE: UNIQUE_VIOLATION

        if is_unique:
            if constraint == "org_email_unique":
                code, msg, field = (
                    "ORG_EMAIL_TAKEN",
                    "Organization email already in use",
                    "email",
                )
            elif constraint == "org_slug_unique":
                code, msg, field = (
                    "ORG_NAME_TAKEN",
                    "Organization name is not available",
                    "name",
                )
            elif constraint == "user_email_unique":
                code, msg, field = (
                    "ADMIN_EMAIL_TAKEN",
                    "Admin email already in use",
                    "admin_email",
                )
            elif constraint == "app_org_slug_unique":
                code, msg, field = (
                    "APP_SLUG_TAKEN",
                    "Application slug already in use",
                    "slug",
                )
            elif constraint == "did_document_did_unique":
                code, msg, field = "DID_TAKEN", "DID already exists", "did"
            elif constraint == "api_key_prefix_unique":
                code, msg, field = (
                    "API_KEY_PREFIX_TAKEN",
                    "API key prefix already exists",
                    "key_prefix",
                )
            elif constraint == "api_key_hash_unique":
                code, msg, field = "API_KEY_CONFLICT", "API key already exists", None
            elif constraint == "did_key_ref_unique":
                code, msg, field = (
                    "KEY_ID_TAKEN",
                    "Key id already exists for this DID",
                    "key_id",
                )

        errors = {field: ["already taken"]} if field else None
        return _envelope(request, message=msg, status=status, code=code, errors=errors)

    @api.exception_handler(DjangoValidationError)
    def on_django_validation_error(request, exc: DjangoValidationError):
        errors = exc.message_dict if hasattr(exc, "message_dict") else exc.messages
        return _envelope(
            request,
            message="Validation error",
            status=422,
            code="VALIDATION_ERROR",
            errors=errors,
        )

    @api.exception_handler(NinjaValidationError)
    def on_ninja_validation_error(request, exc: NinjaValidationError):
        return _envelope(
            request,
            message="Validation error",
            status=422,
            code="VALIDATION_ERROR",
            errors=exc.errors,
        )

    @api.exception_handler(Exception)
    def on_unexpected_error(request, exc: Exception):
        err = None
        extra = {}
        if settings.DEBUG:
            err = str(exc)
            extra["trace"] = traceback.format_exc(limit=20)
        return _envelope(
            request,
            message="Unexpected error",
            status=500,
            code="INTERNAL_ERROR",
            errors=err,
            extra=extra if settings.DEBUG else None,
        )
