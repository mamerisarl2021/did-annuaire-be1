from ninja import Schema


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


