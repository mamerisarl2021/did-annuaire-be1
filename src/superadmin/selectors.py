from django.db.models import Prefetch, QuerySet, Q

from src.organizations.models import Organization
from src.users.models import User, UserRole
from django.db.models import Max, Exists, OuterRef, Q, QuerySet

from src.dids.models import DID, DIDDocument

def organization_list_all() -> QuerySet[Organization]:
    """Return all organizations (no filter)."""
    return Organization.objects.all().order_by("-created_at")


def organization_list_by_status(*, status: str) -> QuerySet[Organization]:
    """Return organizations filtered by a single status."""
    return Organization.objects.filter(status=status).order_by("-created_at")


def organization_list(
    *, status: str = None, search: str = None
) -> QuerySet[Organization]:
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


def organization_list_with_admins(
    *, status: str = None, search: str = None
) -> QuerySet[Organization]:
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
        User.objects.filter(role__contains=[UserRole.ORG_ADMIN])
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


def did_list_all_with_context(
        *,
        q: str | None = None,
        organization_id: str | None = None,
        status: str | None = None,
) -> QuerySet:
    """
    Global queryset for DIDs (superadmin scope), annotated for list views.
    - q: search in did and document_type (icontains)
    - organization_id: filter by organization
    - status: filter by DID.status (DRAFT/ACTIVE/DEACTIVATED)
    """
    prod_active_exists = DIDDocument.objects.filter(
        did_id=OuterRef("id"),
        environment="PROD",
        is_active=True,
    )

    qs = (
        DID.objects.all()
        .annotate(
            latest_version=Max("documents__version"),
            is_published=Exists(prod_active_exists),
        )
        .select_related("organization", "owner")
        .order_by("-created_at")
    )

    if organization_id:
        qs = qs.filter(organization_id=organization_id)

    if status:
        qs = qs.filter(status=status)

    if q:
        qs = qs.filter(Q(did__icontains=q) | Q(document_type__icontains=q))

    return qs


def users_list_all(
    *,
    q: str | None = None,
    organization_id: str | None = None,
    role: str  | None= None,          # e.g., "ORG_ADMIN", "AUDITOR", "ORG_MEMBER"
    is_active: bool | None = None,     # true/false
    status: str | None = None,         # if your User.status is used
) -> QuerySet:
    """
    Superadmin scope: build a filtered queryset for users across all organizations.
    Filters:
      - q: icontains on email/first_name/last_name/phone
      - organization_id: exact match
      - role: JSON membership (role__contains=[role])
      - is_active: boolean
      - status: exact match (if applicable in your model)
    """
    qs = (
        User.objects.all()
        .select_related("organization")
        .order_by("-created_at", "-id")
    )

    if organization_id:
        qs = qs.filter(organization_id=organization_id)

    if role:
        qs = qs.filter(role__contains=[role])

    if is_active is not None:
        qs = qs.filter(is_active=bool(is_active))

    if status:
        qs = qs.filter(status=status)

    if q:
        qs = qs.filter(
            Q(email__icontains=q)
            | Q(first_name__icontains=q)
            | Q(last_name__icontains=q)
            | Q(phone__icontains=q)
        )

    return qs
