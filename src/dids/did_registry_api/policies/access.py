def can_manage_did(user, did_obj) -> bool:
    """
    Owner-only: seul le créateur du DID peut gérer/rotater/mettre à jour.
    """
    return getattr(user, "id", None) == getattr(did_obj, "owner_id", None)

def is_org_admin(user, org) -> bool:
    """
    ORG_ADMIN de l'organisation (ou superuser). Utilise des heuristiques sûres.
    """
    if getattr(user, "is_superuser", False):
        return True
    role = getattr(user, "role", None)
    if role == "ORG_ADMIN" and getattr(user, "organization_id", None) == getattr(org, "id", None):
        return True
    try:
        # Si vous utilisez Django perms avec objet
        return bool(user.has_perm("dids.org_admin", org))
    except Exception:
        return False

def can_publish_prod(user, org) -> bool:
    """
    Droit explicite de publier en PROD (ou superuser / org admin).
    """
    if getattr(user, "is_superuser", False):
        return True
    if is_org_admin(user, org):
        return True
    try:
        return bool(user.has_perm("dids.can_publish_prod", org))
    except Exception:
        return False
