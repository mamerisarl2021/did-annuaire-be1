
from django.db.models import QuerySet
from src.dids.models import PublishRequest

def list_publish_requests(org_id: str | str, status: str | None, offset: int, limit: int) -> QuerySet[PublishRequest]:
    """
    Read-only selector: liste les demandes d'approbation pour une organisation.
    Applique select_related pour éviter les N+1 et borne le paging.
    """
    qs = (PublishRequest.objects
          .select_related("did", "did__organization", "requested_by", "decided_by", "did_document")
          .filter(did__organization_id=org_id))
    if status:
        qs = qs.filter(status=status)
    off = max(0, int(offset or 0))
    lim = min(200, max(1, int(limit or 50)))
    return qs.order_by("-created_at")[off: off + lim]
    