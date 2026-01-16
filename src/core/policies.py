from src.core.exceptions import APIError
from src.users.models import UserRole


def ensure_superuser(user) -> None:
    if getattr(user, "role", None) != UserRole.SUPERUSER:
        raise APIError(message="Only SUPERUSER can access this", code="FORBIDDEN", status=403)


def ensure_org_member(user, org_id) -> None:
    """
    Enforce that the caller belongs to the given organization.
    org_id may be UUID (obj) or str — compare as strings.
    """
    user_org = getattr(user, "organization_id", None)
    if not user_org or str(user_org) != str(org_id):
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)


def ensure_role_in(user, *roles) -> None:
    if getattr(user, "role", None) not in roles:
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)
