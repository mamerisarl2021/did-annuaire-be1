from __future__ import annotations
from django.db.models import Count

from src.dids.models import DID, DIDDocument, PublishRequest


def get_publish_request_for_update(pr_id: str) -> PublishRequest:
    """
    Loads a publish request by ID with a row-level lock for update
    """
    return PublishRequest.objects.select_for_update().get(pk=pr_id)


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