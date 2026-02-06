def _admin_from_prefetch(org):
    admins = getattr(org, "admin_user", []) or []
    return admins[0] if admins else None


def org_to_list_dto_superadmin(org) -> dict:
    admin = _admin_from_prefetch(org)
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "type": org.type,
        "country": org.country,
        "email": org.email,
        "address": org.address,
        "status": org.status,
        "created_at": org.created_at.isoformat(),
        "admin": ({"id": admin.id, "email": admin.email} if admin else None),
    }


def org_to_detail_dto_superadmin(org) -> dict:
    admin = _admin_from_prefetch(org)
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "type": org.type,
        "country": org.country,
        "email": org.email,
        "phone": org.phone,
        "address": org.address,
        "status": org.status,
        "allowed_email_domains": org.allowed_email_domains,
        "validated_at": org.validated_at.isoformat() if org.validated_at else None,
        "refusal_reason": org.refusal_reason,
        "created_at": org.created_at.isoformat(),
        "admin": (
            {
                "id": admin.id,
                "email": admin.email,
                "first_name": admin.first_name,
                "last_name": admin.last_name,
                "phone": admin.phone,
                "functions": getattr(admin, "functions", ""),
                "status": admin.status,
            }
            if admin
            else None
        ),
        "documents": {
            "authorization_document_url": org.authorization_document.url
            if org.authorization_document
            else None,
            "justification_document_url": org.justification_document.url
            if org.justification_document
            else None,
            "authorization_document_name": org.authorization_document.name
            if org.authorization_document
            else None,
            "justification_document_name": org.justification_document.name
            if org.justification_document
            else None,
        },
    }


def user_to_list_dto_superadmin(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "phone": u.phone,
        "role": u.role,
        "status": u.status,
        "created_at": u.created_at.isoformat()
        if getattr(u, "created_at", None)
        else None,
        "organization": {
            "id": u.organization.id if u.organization else None,
            "name": u.organization.name if u.organization else None,
        },
    }
