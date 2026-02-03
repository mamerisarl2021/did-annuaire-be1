
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


def _accumulate_purposes(rows: List[List[str]]) -> Dict[str, int]:
    acc: Dict[str, int] = {}
    for arr in rows:
        if not arr:
            continue
        for p in arr:
            if not isinstance(p, str):
                continue
            acc[p] = acc.get(p, 0) + 1
    return acc


def _series(queryset, dt_field: str, days: int) -> List[Dict[str, Any]]:
    qs = (
        queryset.filter(**{f"{dt_field}__gte": timezone.now() - timedelta(days=days)})
        .annotate(bucket=TruncDay(dt_field))
        .values("bucket")
        .annotate(count=Count("id"))
        .order_by("bucket")
    )
    return [{"bucket": x["bucket"].date().isoformat(), "count": x["count"]} for x in qs]


@api_controller("/dids", tags=["DIDs"], auth=JWTAuth())
class DIDsStatsController:
    @route.get("/stats")
    def stats(self, request, window_days: int = 30):
        """
        Organization-scoped stats for the caller's organization.
        """
        org_id = getattr(request.user, "organization_id", None)
        if not org_id:
            return JsonResponse(
                {"success": False, "message": "User has no organization context"},
                status=400,
            )

        now = timezone.now()
        since = now - timedelta(days=window_days)

        # Base DID queryset for org
        did_qs = DID.objects.filter(organization_id=org_id)

        # Totals
        dids_total = did_qs.count()
        dids_by_status = {
            row["status"]: row["c"]
            for row in did_qs.values("status").annotate(c=Count("id"))
        }

        docs_draft = DIDDocument.objects.filter(
            did__organization_id=org_id, environment="DRAFT"
        ).count()
        docs_prod_active = DIDDocument.objects.filter(
            did__organization_id=org_id, environment="PROD", is_active=True
        ).count()

        pr_pending = PublishRequest.objects.filter(
            did__organization_id=org_id, status=PublishRequest.Status.PENDING
        ).count()
        pr_approved = PublishRequest.objects.filter(
            did__organization_id=org_id,
            status=PublishRequest.Status.APPROVED,
            decided_at__gte=since,
        ).count()
        pr_rejected = PublishRequest.objects.filter(
            did__organization_id=org_id,
            status=PublishRequest.Status.REJECTED,
            decided_at__gte=since,
        ).count()

        keys_active = UploadedPublicKey.objects.filter(
            did__organization_id=org_id, is_active=True
        ).count()
        rotations_last_window = UploadedPublicKey.objects.filter(
            did__organization_id=org_id, version__gt=1, created_at__gte=since
        ).count()

        cert_count = Certificate.objects.filter(organization_id=org_id).count()
        # compliance distribution
        compliance_rows = (
            Certificate.objects.filter(organization_id=org_id)
            .values("compliance__status")
            .annotate(c=Count("id"))
        )
        compliance_dist = {
            (row["compliance__status"] or "UNKNOWN"): row["c"]
            for row in compliance_rows
        }

        # Breakdown by document_type (DIDs + active PROD)
        dids_by_type = {
            row["document_type"]: row["c"]
            for row in did_qs.values("document_type").annotate(c=Count("id"))
        }
        prod_active_by_type = {
            row["did__document_type"]: row["c"]
            for row in DIDDocument.objects.filter(
                did__organization_id=org_id, environment="PROD", is_active=True
            )
            .values("did__document_type")
            .annotate(c=Count("id"))
        }
        by_document_type = []
        for dt, cnt in dids_by_type.items():
            by_document_type.append(
                {
                    "document_type": dt,
                    "dids": cnt,
                    "prod_active": prod_active_by_type.get(dt, 0),
                }
            )

        # Breakdown by curve from UploadedPublicKey.public_key_jwk.crv
        curves_rows = (
            UploadedPublicKey.objects.filter(did__organization_id=org_id)
            .values("public_key_jwk__crv")
            .annotate(c=Count("id"))
        )
        by_curve = {
            (row["public_key_jwk__crv"] or "unknown"): row["c"] for row in curves_rows
        }

        # Breakdown by purpose (Python accumulation over array field)
        purposes_rows = list(
            UploadedPublicKey.objects.filter(did__organization_id=org_id).values_list(
                "purposes", flat=True
            )
        )
        by_purpose = _accumulate_purposes(purposes_rows)

        # Activity & time series
        published_docs_qs = DIDDocument.objects.filter(
            did__organization_id=org_id, environment="PROD", published_at__isnull=False
        )
        published_last_window = published_docs_qs.filter(published_at__gte=since).count()
        published_series = _series(published_docs_qs, "published_at", window_days)

        rotations_qs = UploadedPublicKey.objects.filter(
            did__organization_id=org_id, version__gt=1
        )
        rotations_series = _series(rotations_qs, "created_at", window_days)

        # Pending requests (latest 10)
        pending_reqs = list(
            PublishRequest.objects.filter(
                did__organization_id=org_id, status=PublishRequest.Status.PENDING
            )
            .select_related("did", "requested_by", "did_document")
            .order_by("-created_at")[:10]
        )
        pending_requests = [
            {
                "id": str(pr.id),
                "did": pr.did.did,
                "version": pr.did_document.version,
                "requested_by": getattr(pr.requested_by, "email", None),
                "requested_at": pr.created_at.isoformat() if pr.created_at else None,
            }
            for pr in pending_reqs
        ]

        # Top most recent publishes (latest 5)
        recent_publishes_qs = (
            DIDDocument.objects.filter(
                did__organization_id=org_id,
                environment="PROD",
                is_active=True,
                published_at__isnull=False,
            )
            .select_related("did")
            .order_by("-published_at")[:5]
        )
        recent_publishes = [
            {
                "did": doc.did.did,
                "version": doc.version,
                "published_at": doc.published_at.isoformat()
                if doc.published_at
                else None,
                "published_relpath": doc.published_relpath,
            }
            for doc in recent_publishes_qs
        ]

        payload = {
            "scope": "org",
            "organization_id": str(org_id),
            "as_of": now.isoformat(),
            "window_days": window_days,
            "totals": {
                "dids": dids_total,
                "dids_by_status": dids_by_status,
                "documents": {"draft": docs_draft, "prod_active": docs_prod_active},
                "publish_requests": {
                    "pending": pr_pending,
                    "approved_last_window": pr_approved,
                    "rejected_last_window": pr_rejected,
                },
                "keys": {
                    "active_uploaded_keys": keys_active,
                    "rotations_last_window": rotations_last_window,
                },
                "certificates": {
                    "count": cert_count,
                    "compliance": compliance_dist,
                },
            },
            "breakdowns": {
                "by_document_type": by_document_type,
                "by_curve": by_curve,
                "by_purpose": by_purpose,
            },
            "activity": {
                "publish_prod": {"count": published_last_window},
                "rotations": {"count": rotations_last_window},
            },
            "time_series": {
                "published_prod": published_series,
                "rotations": rotations_series,
            },
            "pending_requests": pending_requests,
            "top": {"most_recent_publishes": recent_publishes},
        }
        return JsonResponse(payload, status=200)