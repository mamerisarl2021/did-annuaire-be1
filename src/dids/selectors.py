from __future__ import annotations
from django.db.models import Count
from django.conf import settings
from django.db.models.functions import Random

from src.dids.resolver.services import parse_did_web
from src.dids.models import DID, DIDDocument, PublishRequest


def get_publish_request_for_update(pr_id: str) -> PublishRequest:
    """
    Loads a publish request by ID with a row-level lock for update
    """
    return PublishRequest.objects.select_for_update().get(pk=pr_id)


def random_prod_did_urls(limit: int = 10) -> list[str]:
    """
    Return up to `limit` random public DID URLs for active PROD documents.
    """
    qs = (
        DIDDocument.objects
        .filter(environment="PROD", is_active=True)
        .select_related("did")
        .order_by(Random())[: max(1, min(int(limit or 10), 100))]
    )

    urls: list[str] = []
    for doc in qs:
        # If we have a stored relative path, prefer it
        rel = (doc.published_relpath or "").lstrip("/") if doc.published_relpath else None
        if rel:
            host = getattr(settings, "DID_DOMAIN_HOST", None)
            if host:
                urls.append(f"https://{host}/{rel}")
                continue
            # Fallback to DID host if DID_DOMAIN_HOST is not set
            host_from_did, *_ = parse_did_web(doc.did.did)
            urls.append(f"https://{host_from_did}/{rel}")
            continue

        # Fallback: derive from DID parts
        host, org, user, doc_type = parse_did_web(doc.did.did)
        urls.append(f"https://{host}/{org}/{user}/{doc_type}/did.json")

    return urls

def registry_stats_for_org(organization_id) -> dict[str, object]:
    """
    Read-only aggregation of DID/DIDDocument stats for a single organization.
    Returns:
      {
        "total": int,
        "published": int,
        "draft": int,
        "deactivated": int,
        "by_environment": { "prod": int, "draft": int }
      }
    """
    did_qs = DID.objects.filter(organization_id=organization_id)

    total = did_qs.count()
    published = did_qs.filter(status=DID.DIDStatus.ACTIVE).count()
    draft = did_qs.filter(status=DID.DIDStatus.DRAFT).count()
    deactivated = did_qs.filter(status=DID.DIDStatus.DEACTIVATED).count()

    prod_count = DIDDocument.objects.filter(
        did__organization_id=organization_id, environment="PROD", is_active=True
    ).count()
    draft_env_count = DIDDocument.objects.filter(
        did__organization_id=organization_id, environment="DRAFT"
    ).count()

    return {
        "total": total,
        "published": published,
        "draft": draft,
        "deactivated": deactivated,
        "by_environment": {
            "prod": prod_count,
            "draft": draft_env_count,
        },
    }
    
def publish_requests_stats_for_org(organization_id) -> dict[str, int]:
    """
    Read-only aggregation of PublishRequest stats for a single organization.
    Returns:
      { "total": int, "pending": int, "approved": int, "rejected": int }
    """
    qs = PublishRequest.objects.filter(did__organization_id=organization_id)

    return {
        "total": qs.count(),
        "pending": qs.filter(status=PublishRequest.Status.PENDING).count(),
        "approved": qs.filter(status=PublishRequest.Status.APPROVED).count(),
        "rejected": qs.filter(status=PublishRequest.Status.REJECTED).count(),
    }