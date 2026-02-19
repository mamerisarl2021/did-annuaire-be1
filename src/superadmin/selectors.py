from django.db.models import (Count, Prefetch, QuerySet, Q, Max, Exists, OuterRef)
from django.db.models.expressions import RawSQL

from src.dids.models import DID, DIDDocument, PublishRequest
from src.organizations.models import Organization
from src.users.models import User, UserRole


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
    List organisations with optional filters.

    Args:
        status: Filter by status (PENDING, ACTIVE, SUSPENDED, REFUSED)
        search: Recherche dans name et slug
    """
    qs = Organization.objects.all()

    if status:
        qs = qs.filter(status=status)

    if search:
        search_term = search.strip()
        qs = qs.filter(Q(name__icontains=search_term) | Q(slug__icontains=search_term))

    return qs.order_by("-created_at")


def organization_list_with_admins(
    *, status: str = None, search: str = None
) -> QuerySet[Organization]:
    """
    List organisations with ORG_ADMIN prefetched.
    """
    qs = organization_list(status=status, search=search)
    return qs.prefetch_related(_admin_prefetch())


def organization_get_with_admin(*, org_id) -> Organization:
    """Single organisation avec son ORG_ADMIN prefetched."""
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


def did_list_all_with_context(*, q: str | None = None, organization_id: str | None = None, status: str | None = None,
                              ) -> QuerySet:
    """
    Global queryset for DIDs (superadmin scope), annotated for list views.
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


def users_list_all(*, q: str | None = None, organization_id: str | None = None,
                   role: str | None = None,  # e.g., "ORG_ADMIN", "AUDITOR", "ORG_MEMBER"
                   is_active: bool | None = None,  # true/false
                   status: str | None = None,  # if your User.status is used
) -> QuerySet:
    """
    Superadmin scope: filtered queryset for users across all organizations.
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


# ---------------------------------------------------------------------------
# Publish requests (superadmin scope — all orgs)
# ---------------------------------------------------------------------------

def publish_request_list_all(
    *,
    organization_id: str | None = None,
    status: str | None = None,
    environment: str | None = None,
    q: str | None = None,
) -> QuerySet[PublishRequest]:
    """
    Read-only selector: all publish requests across every organization.

    Filters:
        organization_id: restrict to a single org
        status: PENDING / APPROVED / REJECTED
        environment: PROD
        q: search in DID identifier
    """
    qs = (
        PublishRequest.objects.all()
        .select_related(
            "did",
            "did__organization",
            "requested_by",
            "decided_by",
            "did_document",
        )
        .order_by("-created_at")
    )

    if organization_id:
        qs = qs.filter(did__organization_id=organization_id)

    if status:
        qs = qs.filter(status=status)

    if environment:
        qs = qs.filter(environment=environment)

    if q:
        qs = qs.filter(did__did__icontains=q)

    return qs

# ---------------------------------------------------------------------------
# Stats — DIDs (superadmin, all orgs)
# ---------------------------------------------------------------------------

def did_stats_all() -> dict:
    """
    Platform-wide DID statistics.

    Returns:
        total, by_status, by_environment, publish_requests,
        top_organizations (top 5 by DID count),
        by_organization (full breakdown per org).
    """
    did_qs = DID.objects.all()
    doc_qs = DIDDocument.objects.all()
    pr_qs = PublishRequest.objects.all()

    # --- totals ---
    total = did_qs.count()

    # --- by status ---
    by_status_rows = did_qs.values("status").annotate(count=Count("id"))
    by_status = {row["status"].lower(): row["count"] for row in by_status_rows}

    # --- by environment (active docs only for PROD, all for DRAFT) ---
    prod_count = doc_qs.filter(environment="PROD", is_active=True).count()
    draft_env_count = doc_qs.filter(environment="DRAFT").count()

    # --- publish requests ---
    pr_rows = pr_qs.values("status").annotate(count=Count("id"))
    publish_requests = {row["status"].lower(): row["count"] for row in pr_rows}

    # --- top 5 organizations by DID count ---
    top_orgs_rows = (
        did_qs.values("organization_id", "organization__name")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    top_organizations = [
        {
            "id": str(row["organization_id"]),
            "name": row["organization__name"],
            "count": row["count"],
        }
        for row in top_orgs_rows
    ]

    # --- by_organization (full breakdown) ---
    org_rows = (
        did_qs.values("organization_id", "organization__name", "status")
        .annotate(count=Count("id"))
        .order_by("organization__name", "status")
    )

    org_map: dict[str, dict] = {}
    for row in org_rows:
        org_id = str(row["organization_id"])
        if org_id not in org_map:
            org_map[org_id] = {
                "id": org_id,
                "name": row["organization__name"],
                "total": 0,
            }
        org_map[org_id]["total"] += row["count"]
        org_map[org_id][row["status"].lower()] = row["count"]

    by_organization = sorted(org_map.values(), key=lambda o: o["total"], reverse=True)

    return {
        "total": total,
        "by_status": by_status,
        "by_environment": {
            "prod": prod_count,
            "draft": draft_env_count,
        },
        "publish_requests": publish_requests,
        "top_organizations": top_organizations,
        "by_organization": by_organization,
    }


# ---------------------------------------------------------------------------
# Stats — Users (superadmin, all orgs)
# ---------------------------------------------------------------------------

def users_stats_all() -> dict:
    """
    Platform-wide user statistics.

    Returns:
        total, by_status, by_role,
        top_organizations (top 5 by user count),
        by_organization (full breakdown per org).
    """
    user_qs = User.objects.all()

    # --- total ---
    total = user_qs.count()

    # --- by status ---
    status_rows = user_qs.values("status").annotate(count=Count("id"))
    by_status = {row["status"].lower(): row["count"] for row in status_rows}

    # --- by role (JSON explode) ---
    role_rows = (
        user_qs.annotate(role_item=RawSQL("jsonb_array_elements_text(role)", []))
        .values("role_item")
        .annotate(count=Count("id"))
    )
    by_role = {row["role_item"].lower(): row["count"] for row in role_rows}

    # --- top 5 organizations by user count ---
    top_orgs_rows = (
        user_qs.filter(organization__isnull=False)
        .values("organization_id", "organization__name")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    top_organizations = [
        {
            "id": str(row["organization_id"]),
            "name": row["organization__name"],
            "count": row["count"],
        }
        for row in top_orgs_rows
    ]

    # --- by_organization (full breakdown) ---
    org_rows = (
        user_qs.filter(organization__isnull=False)
        .values("organization_id", "organization__name", "status")
        .annotate(count=Count("id"))
        .order_by("organization__name", "status")
    )

    org_map: dict[str, dict] = {}
    for row in org_rows:
        org_id = str(row["organization_id"])
        if org_id not in org_map:
            org_map[org_id] = {
                "id": org_id,
                "name": row["organization__name"],
                "total": 0,
            }
        org_map[org_id]["total"] += row["count"]
        org_map[org_id][row["status"].lower()] = row["count"]

    by_organization = sorted(org_map.values(), key=lambda o: o["total"], reverse=True)

    return {
        "total": total,
        "by_status": by_status,
        "by_role": by_role,
        "top_organizations": top_organizations,
        "by_organization": by_organization,
    }