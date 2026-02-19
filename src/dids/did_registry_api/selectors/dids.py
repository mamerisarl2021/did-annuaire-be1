from django.shortcuts import get_object_or_404
from django.db.models import (
    QuerySet, Exists, OuterRef, Subquery, Case, When, Value,
    CharField, IntegerField, F, Q,
)
from django.db.models.functions import Coalesce
from src.dids.models import DID, DIDDocument, PublishRequest
from src.dids.utils.validators import DIDRegistrarState


def get_did_or_404(did_str: str) -> DID:
    return get_object_or_404(
        DID.objects.select_related("organization", "owner"), did=did_str
    )


def user_is_owner(user, did_obj: DID) -> bool:
    return getattr(user, "id", None) == getattr(did_obj, "owner_id", None)


def dids_base_qs() -> QuerySet[DID]:
    # Centralize select_related/order_by to avoid N+1 and keep a consistent ordering
    return DID.objects.select_related("organization", "owner").order_by("-id")


def dids_for_owner(owner_id) -> QuerySet[DID]:
    return dids_base_qs().filter(owner_id=owner_id)


def dids_for_org(org_id) -> QuerySet[DID]:
    return dids_base_qs().filter(organization_id=org_id)


def dids_for_org_with_state(
    org_id,
    *,
    status: str | None = None,
    environment: str | None = None,
    q: str | None = None,
):
    """
    Organisation-scoped DID queryset annotated with registrar-like state.

    Filters:
        status: DID status — DRAFT | ACTIVE | DEACTIVATED
        environment: document environment — PROD | DRAFT
        q: search in DID identifier or document_type
    """
    # latest active PROD version
    prod_active_ver_sq = (
        DIDDocument.objects
        .filter(did_id=OuterRef("id"), environment="PROD", is_active=True)
        .values("version")[:1]
    )

    # latest DRAFT version
    draft_ver_sq = (
        DIDDocument.objects
        .filter(did_id=OuterRef("id"), environment="DRAFT")
        .order_by("-version")
        .values("version")[:1]
    )

    # pending publish request exists
    pending_pr_exists = PublishRequest.objects.filter(
        did_id=OuterRef("id"),
        environment="PROD",
        status=PublishRequest.Status.PENDING,
    )

    base = dids_for_org(org_id).annotate(
        latest_prod_ver=Coalesce(
            Subquery(prod_active_ver_sq), Value(0), output_field=IntegerField()
        ),
        latest_draft_ver=Coalesce(
            Subquery(draft_ver_sq), Value(0), output_field=IntegerField()
        ),
        has_pending_pr=Exists(pending_pr_exists),
    )

    # --- Filters (business logic stays in selector) ---

    if status:
        base = base.filter(status=status)

    if environment == "PROD":
        # Only DIDs that have an active PROD document
        base = base.filter(
            Exists(
                DIDDocument.objects.filter(
                    did_id=OuterRef("id"), environment="PROD", is_active=True,
                )
            )
        )
    elif environment == "DRAFT":
        # Only DIDs that have NOT been published to PROD
        base = base.exclude(
            Exists(
                DIDDocument.objects.filter(
                    did_id=OuterRef("id"), environment="PROD", is_active=True,
                )
            )
        )

    if q:
        base = base.filter(
            Q(did__icontains=q) | Q(document_type__icontains=q)
        )

    # Compute registrar-like state for the list rows
    return base.annotate(
        state=Case(
            When(
                status=DID.DIDStatus.DEACTIVATED,
                then=Value(DIDRegistrarState.FINISHED.value),
            ),
            When(has_pending_pr=True, then=Value(DIDRegistrarState.WAIT.value)),
            When(
                Q(latest_draft_ver__gt=F("latest_prod_ver")),
                then=Value(DIDRegistrarState.ACTION.value),
            ),
            When(
                Q(latest_prod_ver__gt=Value(0)),
                then=Value(DIDRegistrarState.FINISHED.value),
            ),
            default=Value(DIDRegistrarState.ACTION.value),
            output_field=CharField(),
        )
    )