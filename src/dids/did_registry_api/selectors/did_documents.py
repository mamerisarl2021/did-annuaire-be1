from django.db.models import Max
from src.dids.models import DID, DIDDocument


def latest_version(did: DID) -> int:
    return did.documents.aggregate(Max("version")).get("version__max") or 0


def latest_draft(did: DID) -> DIDDocument | None:
    return did.documents.filter(environment="DRAFT").order_by("-version").first()


def active_prod(did: DID) -> DIDDocument | None:
    return (
        did.documents.filter(environment="PROD", is_active=True)
        .order_by("-version")
        .first()
    )


def candidate_for_publish(did: DID, version: int | None = None) -> DIDDocument | None:
    if version is not None:
        return did.documents.filter(version=version).first()
    return latest_draft(did)
