def org_to_list_dto_admin(org) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "type": org.type,
        "country": org.country,
        "email": org.email,
        "created_at": org.created_at.isoformat(),
    }

def org_to_detail_dto_admin(org) -> dict:
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
        "max_users": org.max_users,
        "max_applications": org.max_applications,
        "validated_at": org.validated_at.isoformat() if org.validated_at else None,
        "refusal_reason": org.refusal_reason if org.refusal_reason else None,
        "created_at": org.created_at.isoformat(),
        "documents": {
            "authorization_document_url": org.authorization_document.url if org.authorization_document else None,
            "justification_document_url": org.justification_document.url if org.justification_document else None,
            "authorization_document_name": org.authorization_document.name if org.authorization_document else None,
            "justification_document_name": org.justification_document.name if org.justification_document else None,
        },
    }
