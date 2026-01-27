from django.db.models import Prefetch, QuerySet, Q

from src.organizations.models import Organization
from src.users.models import User, UserRole

def organization_list_all() -> QuerySet[Organization]:
    """Return all organizations (no filter)."""
    return Organization.objects.all().order_by("-created_at")
    
def organization_list_by_status(*, status: str) -> QuerySet[Organization]:
    """Return organizations filtered by a single status."""
    return Organization.objects.filter(status=status).order_by("-created_at")
    
def organization_list(*, status: str = None, search: str = None) -> QuerySet[Organization]:
    """
    List organisations with optional filters

    Args:
        status: Filter by status (PENDING, ACTIVE, SUSPENDED, REFUSED)
        search: Recherche dans name et slug

    Returns:
        Organization queryset ordered by descending creation date
    """
    qs = Organization.objects.all()

    # Filtre par statut
    if status:
        qs = qs.filter(status=status)

    # Recherche textuelle (nom ou slug)
    if search:
        search_term = search.strip()
        qs = qs.filter(Q(name__icontains=search_term) | Q(slug__icontains=search_term))

    return qs.order_by("-created_at")
    
def organization_list_with_admins(*, status: str = None, search: str = None) -> QuerySet[Organization]:
    """
    List organisations ORG_ADMIN prefetched

    Args:
        status: Filtre by status
        search: Search in name and slug
    """
    qs = organization_list(status=status, search=search)
    return qs.prefetch_related(_admin_prefetch())

def organization_get_with_admin(*, org_id) -> Organization:
    """Single organisation avec son ORG_ADMIN prefetched"""
    return Organization.objects.prefetch_related(_admin_prefetch()).get(id=org_id)

def _admin_prefetch() -> Prefetch:
    admin_qs = (
        User.objects.filter(role=UserRole.ORG_ADMIN)
        .only(
            "id",
            "email",
            "first_name",
            "last_name",
            "phone",
            "functions",
            "status",
            "invitation_sent_at",
            "invitation_accepted_at",
            "created_at",
        )
        .order_by("created_at")
    )
    return Prefetch("users", queryset=admin_qs, to_attr="admin_user")
