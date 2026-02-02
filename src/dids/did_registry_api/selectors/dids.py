from django.db.models import QuerySet
from django.shortcuts import get_object_or_404

from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.models import DID
from src.organizations.models import Organization


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
