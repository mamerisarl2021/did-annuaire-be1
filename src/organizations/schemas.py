from ninja import Schema
from pydantic import field_validator


class OrgCreatePayload(Schema):
    """
    Multipart payload.
    Files:
      - authorization_document (required)
      - justification_document (optional)
    """

    allowed_email_domains: list[str]
    name: str
    org_type: str
    country: str
    email: str
    phone: str
    address: str
    admin_email: str
    admin_first_name: str
    admin_last_name: str
    admin_phone: str
    functions: str


class AdminOrgFilterParams(Schema):
    status: str | None = None

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str | None) -> str | None:
        if v is None:
            return v
        s = v.upper().strip()
        allowed = {"ACTIVE", "SUSPENDED"}
        if s not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return s
