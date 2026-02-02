from src.organizations.models import Organization, OrganizationStatus
from src.users.models import User, UserRole
from django.db.models import QuerySet


def organization_list_by_admins(*, status: str | None = None, user: User) -> QuerySet:
    """
    Returns a queryset of organizations visible to the given user.
    - ORG_ADMIN: only their own org
    - Optional: filter by status
    """
    qs = Organization.objects.all()

    # Scope by org for ORG_ADMIN
    if UserRole.ORG_ADMIN in user.role:
        if user.organization_id is not None:
            qs = qs.filter(id=user.organization_id)
        else:
            # should not happen, maybe superuser? fallback empty
            qs = qs.none()

    # Apply status filter
    if status:
        qs = qs.filter(status=status.upper())

    # Order by creation date descending
    qs = qs.order_by("-created_at")

    return qs


def organization_stats_for_admin(*, user: User) -> dict[str, int]:
    """
    Returns organization counts scoped to the ORG_ADMIN's organization context.

    Only the organization that the admin belongs to is counted.
    """
    org_id = user.organization_id

    # If somehow no org, return zeros
    if not org_id:
        return {"all": 0, "active": 0, "suspended": 0}

    qs = Organization.objects.filter(id=org_id)

    return {
        "all": qs.count(),
        "active": qs.filter(status=OrganizationStatus.ACTIVE).count(),
        "suspended": qs.filter(status=OrganizationStatus.SUSPENDED).count(),
    }
