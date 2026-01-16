# src/organizations/schemas.py (AJOUT)

import re
from ninja import Schema
from pydantic import field_validator


class OrgCreatePayload(Schema):
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

    @field_validator('allowed_email_domains')
    @classmethod
    def parse_domains(cls, v):
        if isinstance(v, str):
            return [domain.strip() for domain in v.split(',') if domain.strip()]
        return v

    @field_validator('allowed_email_domains')
    @classmethod
    def validate_email_domains(cls, v):
        if not v:
            raise ValueError('At least one email domain is required')

        validated_domains = []
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

        for domain in v:
            if not domain_pattern.match(domain):
                raise ValueError(f'Invalid domain format: "{domain}". Must be like "example.com"')
            validated_domains.append(domain)

        return validated_domains


class OrgRefusePayload(Schema):
    reason: str


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