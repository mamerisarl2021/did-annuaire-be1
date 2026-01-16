def user_to_list_dto(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "status": u.status,
        "created_at": u.created_at.isoformat() if getattr(u, "created_at", None) else None,
    }

def user_to_detail_dto(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "full_name": u.full_name,
        "phone": u.phone,
        "role": u.role,
        "status": u.status,
        "organization": {
            "id": u.organization.id if u.organization else None,
            "name": u.organization.name if u.organization else None,
        },
        "totp_enabled": u.totp_enabled,
        "last_login": u.last_login,
        "can_publish_prod": u.can_publish_prod,
        "functions": getattr(u, "functions", None),
    }
