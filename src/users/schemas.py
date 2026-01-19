from ninja import Schema
from pydantic import field_validator


ALLOWED_ROLES = {"SUPERUSER", "ORG_ADMIN", "ORG_MEMBER", "AUDITOR"}
ALLOWED_STATUSES = {"PENDING", "ACTIVE", "SUSPENDED", "DEACTIVATED"}


class UserCreatePayload(Schema):
    email: str
    first_name: str
    last_name: str
    phone: str
    role: str
    functions: str | None = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.strip().lower()

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        role = (v or "").upper().strip()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}")
        return role

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, v: str) -> str:
        return v.strip()


class UserUpdatePayload(Schema):
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    role: str | None = None
    functions: str | None = None
    status: str | None = None

    @field_validator("role")
    @classmethod
    def _validate_role_optional(cls, v: str | None) -> str | None:
        if v is None:
            return v
        role = v.upper().strip()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}")
        return role

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return v
        s = v.upper().strip()
        if s not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
        return s

    @field_validator("phone")
    @classmethod
    def _normalize_phone_optional(cls, v: str | None) -> str | None:
        return v.strip() if isinstance(v, str) else v


class UserActivatePayload(Schema):
    token: str
    password: str
    enable_totp: bool = False
    code: str | None = None

    @field_validator("token")
    @classmethod
    def _token_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("token is required")
        return v.strip()

    @field_validator("password")
    @classmethod
    def _password_basic_rules(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class OTPVerifyPayload(Schema):
    code: str


class UserFilterParams(Schema):
    """Paramètres de filtrage et recherche"""

    status: str | None = None
    role: str | None = None
    search: str | None = None

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return v
        s = v.upper().strip()
        if s not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
        return s

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        r = v.upper().strip()
        if r not in ALLOWED_ROLES:
            raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}")
        return r
