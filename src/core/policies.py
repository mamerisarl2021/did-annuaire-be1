from src.core.exceptions import APIError
from src.users.models import UserRole


def ensure_superuser(user) -> None:
    if not user.is_platform_admin:
        raise APIError(
            message="Only platform administrators can access this",
            code="FORBIDDEN",
            status=403,
        )


def ensure_org_member(user, org_id) -> None:
    """Ensure the caller belongs to the given organization (UUID or str)."""
    org_id_str = str(org_id)
    if str(getattr(user, "organization_id", None)) != org_id_str:
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)


def ensure_role_in(user, *roles) -> None:
    user_roles = getattr(user, "role", [])

    if not any(r in roles for r in user_roles):
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)
