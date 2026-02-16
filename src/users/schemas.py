from uuid import UUID
from ninja import Schema
from pydantic import field_validator, EmailStr
from datetime import datetime


class UserCreatePayload(Schema):
    email: EmailStr
    first_name: str
    last_name: str
    phone: str
    is_auditor: bool = False
    functions: str | None = None
    can_publish_prod: bool = False


class UserListItem(Schema):
    id: UUID
    email: str
    full_name: str
    role: list[str]
    status: str
    created_at: datetime
    organization: str | None = None
    invited_by: str | None = None
    functions: str | None = None
    invitation_accepted_at: datetime | None = None
    can_publish_prod: bool


class FilterParams(Schema):
    status: str | None = None
    search: str | None = None


class OrganizationInfo(Schema):
    id: UUID | None = None
    name: str | None = None


class UserProfileSchema(Schema):
    id: UUID
    email: str
    first_name: str
    last_name: str
    phone: str
    role: list[str]
    status: str
    organization: OrganizationInfo
    totp_enabled: bool
    last_login: datetime | None = None
    can_publish_prod: bool
    functions: str | None = None


class OTPVerifyPayload(Schema):
    code: str


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


class UserUpdatePayload(Schema):
    email: str | None
    first_name: str | None
    last_name: str | None
    phone: str | None
    functions: str | None
    can_publish_prod: bool | None
    is_auditor: bool | None


class PasswordResetRequestPayload(Schema):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def _email_normalize(cls, v: str) -> str:
        return v.strip().lower()


class PasswordResetConfirmPayload(Schema):
    token: str
    new_password: str

    @field_validator("token")
    @classmethod
    def _token_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Le token est requis")
        return v.strip()

    @field_validator("new_password")
    @classmethod
    def _password_not_empty(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères")
        return v
