
from __future__ import annotations
from datetime import timedelta
from typing import Any, Dict, List

from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Count, Q
from django.db.models.functions import TruncDay
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth

from src.dids.models import (
    DID,
    DIDDocument,
    PublishRequest,
    UploadedPublicKey,
    Certificate,
)
from src.dids.selectors import (
    registry_stats_for_org,
    publish_requests_stats_for_org,
)

# def _accumulate_purposes(rows: List[List[str]]) -> Dict[str, int]:
#     acc: Dict[str, int] = {}
#     for arr in rows:
#         if not arr:
#             continue
#         for p in arr:
#             if not isinstance(p, str):
#                 continue
#             acc[p] = acc.get(p, 0) + 1
#     return acc


# def _series(queryset, dt_field: str, days: int) -> List[Dict[str, Any]]:
#     qs = (
#         queryset.filter(**{f"{dt_field}__gte": timezone.now() - timedelta(days=days)})
#         .annotate(bucket=TruncDay(dt_field))
#         .values("bucket")
#         .annotate(count=Count("id"))
#         .order_by("bucket")
#     )
#     return [{"bucket": x["bucket"].date().isoformat(), "count": x["count"]} for x in qs]


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class DIDsStatsController:

    @route.get("/stats")
    def registry_stats(self, request):
        """
        Organization-scoped DID/DIDDocument stats for the caller's organization.
        Response:
        {
            total: number,
            published: number,
            draft: number,
            deactivated: number,
            by_environment: { prod: number, draft: number }
        }
        """
        org_id = getattr(request.user, "organization_id", None)
        if not org_id:
            return JsonResponse(
                {"success": False, "message": "User has no organization context"},
                status=400,
            )
    
        data = registry_stats_for_org(org_id)
        return JsonResponse(data, status=200)

    @route.get("/publish-requests/stats")
    def publish_requests_stats(self, request):
        """
        Organization-scoped PublishRequest stats for the caller's organization.
        Response:
        { total: number, pending: number, approved: number, rejected: number }
        """
        org_id = getattr(request.user, "organization_id", None)
        if not org_id:
            return JsonResponse(
                {"success": False, "message": "User has no organization context"},
                status=400,
            )
    
        data = publish_requests_stats_for_org(org_id)
        return JsonResponse(data, status=200)