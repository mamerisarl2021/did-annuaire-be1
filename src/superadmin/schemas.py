from uuid import UUID
from datetime import datetime
from ninja import Schema
from pydantic import field_validator


class OrgFilterParams(Schema):
    """Paramètres de filtrage et recherche pour organisations"""

    status: str | None = None
    search: str | None = None

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return v
        s = v.upper().strip()
        allowed = {"PENDING", "ACTIVE", "SUSPENDED", "REFUSED"}
        if s not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return s


class OrgRefusePayload(Schema):
    reason: str
