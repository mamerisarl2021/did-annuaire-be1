def can_manage_did(user, did_obj) -> bool:
    """
    Owner-only: seul le créateur du DID peut gérer/rotater/mettre à jour.
    """
    return getattr(user, "id", None) == getattr(did_obj, "owner_id", None)


def is_org_admin(user, org) -> bool:
    """
    True if user is platform admin or ORG_ADMIN of the given org.
    """
    if user.is_platform_admin:
        return True

    if user.is_org_admin and user.organization_id == getattr(org, "id", None):
        return True

    return False


def can_publish_prod(user, org) -> bool:
    return user.organization_id == org.id and user.can_publish_prod_effective
