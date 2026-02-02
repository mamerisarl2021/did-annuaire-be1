from ninja import Query, Body
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth
from django.conf import settings

from src.core.apis import BaseAPIController
from src.core.policies import ensure_superuser
from src.api.pagination import Paginator
from src.common.utils import validate_uuid
from src.dids.publishing.selectors import relpaths_for_did
from src.dids.publishing.services import remove_published_path
from src.dids.resolver.services import parse_did_web
from src.organizations.models import Organization
from src.superadmin import selectors as sa_selectors
from .schemas import OrgFilterParams, OrgRefusePayload
from src.superadmin.presenters import (
    org_to_list_dto_superadmin,
    org_to_detail_dto_superadmin,
)
from . import services
from . import selectors
# from src.users import selectors as user_selectors
# from src.users.schemas import FilterParams


@api_controller("/superadmin", tags=["Super Admin"], auth=JWTAuth())
class SuperAdminController(BaseAPIController):
    
    @route.get("/organizations")
    def list_organizations(self, filters: Query[OrgFilterParams]):  # ← MODIFIÉ
        """
        Liste les organisations pour SuperAdmin
        Supporte: status, search (name/slug) + pagination
        """
        user = self.context.request.auth
        ensure_superuser(user)

        qs = sa_selectors.organization_list_with_admins(
            status=filters.status, search=filters.search
        )

        paginator = Paginator(default_page_size=10, max_page_size=20)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [org_to_list_dto_superadmin(o) for o in items]

        # Message dynamique
        msg_parts = []
        if filters.status:
            msg_parts.append(f"status={filters.status}")
        if filters.search:
            msg_parts.append(f"search='{filters.search}'")

        message = "Organizations"
        if msg_parts:
            message += f" ({', '.join(msg_parts)})"

        return self.create_response(
            message=message, data={"items": data, "pagination": meta}, status_code=200
        )

    @route.get("/organizations/{org_id}")
    def get_organization(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        org = selectors.organization_get_with_admin(org_id=org_uuid)
        return self.create_response(
            message="Organization details",
            data=org_to_detail_dto_superadmin(org),
            status_code=200,
        )

    @route.post("/organizations/{org_id}/validate")
    def validate(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_validate(organization_id=org_uuid, validated_by=user)
        return self.create_response(
            message="Organization validated successfully", status_code=200
        )

    @route.post("/organizations/{org_id}/refuse")
    def refuse(self, org_id: str, payload: OrgRefusePayload):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_refuse(organization_id=org_uuid, refused_by=user, reason=payload.reason)
        return self.create_response(message="Organization refused", status_code=200)

    @route.patch("/organizations/{org_id}/toggle-activation")
    def toggle_activation(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        org = services.organization_toggle_activation(organization_id=org_uuid, toggled_by=user)
        return self.create_response(
            message="Organization status updated",
            data={"id": org.id, "status": org.status},
            status_code=200,
        )

    @route.delete("/organizations/{org_id}")
    def delete_org(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_delete(organization_id=org_uuid, deleted_by=user)
        return self.create_response(message="Organization deleted", status_code=200)

    # @route.get("/organizations/users")
    # def list_users(self, filters: Query[UserFilterParams]):
    #     """
    #     Liste TOUS les utilisateurs (toutes organisations)
    #     Requiert: SUPERUSER
    #     Supporte: status, role, search + pagination
    #     """
    #     current_user = self.context.request.auth
    #     ensure_superuser(current_user)

    #     qs = user_selectors.user_list(
    #         status=filters.status, role=filters.role, search=filters.search
    #     )

    #     paginator = Paginator(default_page_size=10, max_page_size=100)
    #     items, meta = paginator.paginate_queryset(qs, self.context.request)

    #     data = [user_to_list_dto_superadmin(u) for u in items]
    #     return self.create_response(
    #         message="All users fetched",
    #         data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
    #         status_code=200,
    #     )

    # @route.get("/organizations/{org_id}/users")
    # def list_organization_users(self, org_id: str, filters: Query[UserFilterParams]):
    #     """
    #     Liste les utilisateurs d'UNE organisation spécifique
    #     Requiert: SUPERUSER
    #     Supporte: status, role, search + pagination
    #     """
    #     current_user = self.context.request.auth
    #     ensure_superuser(current_user)

    #     org_uuid = validate_uuid(org_id)
    #     organization = get_object_or_404(Organization, id=org_uuid)

    #     qs = user_selectors.user_list(
    #         organization=organization,
    #         status=filters.status,
    #         role=filters.role,
    #         search=filters.search,
    #     )

    #     paginator = Paginator(default_page_size=10, max_page_size=100)
    #     items, meta = paginator.paginate_queryset(qs, self.context.request)

    #     data = [user_to_list_dto_superadmin(u) for u in items]
    #     return self.create_response(
    #         message=f"Users from {organization.name} fetched",
    #         data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
    #         status_code=200,
    #     )

    # @route.post("/users/{user_id}/resend-invite")
    # def resend_invite(self, user_id: str):
    #     user = self.context.request.auth
    #     ensure_superuser(user)
    #     sa_services.user_resend_invite(
    #         user_id=validate_uuid(user_id), requested_by=user
    #     )
    #     return self.create_response(message="Invitation re-sent", status_code=200)

    @route.get("/organizations/stats")
    def get_organizations_stats(self):
        """
        Statistiques des organisations par statut
        Requiert: SUPERUSER
        """
        user = self.context.request.auth
        ensure_superuser(user)

        from src.organizations.models import OrganizationStatus

        stats = {
            "all": Organization.objects.count(),
            "pending": Organization.objects.filter(
                status=OrganizationStatus.PENDING
            ).count(),
            "active": Organization.objects.filter(
                status=OrganizationStatus.ACTIVE
            ).count(),
            "suspended": Organization.objects.filter(
                status=OrganizationStatus.SUSPENDED
            ).count(),
            "refused": Organization.objects.filter(
                status=OrganizationStatus.REFUSED
            ).count(),
        }

        return self.create_response(
            message="Organizations statistics", data=stats, status_code=200
        )

    @route.post("/cleanup")
    def cleanup_published_folder(self, request, body: dict = Body(...)):
        """
        Superuser-only. Remove a published path under DIDS_ROOT.
        Body:
        { "did": "<did:web:...>",
            "scope": "doc_type" | "user" | "org",   # default "doc_type"
            "prune_empty_parents": false            # applies when scope != "org"
        }
        Validates host and path containment; nginx remains RO; deletion is done by backend RW mount.
        """
        if not getattr(self.context.request.auth, "is_superuser", False):
            raise HttpError(403, "Forbidden")

        did = (body or {}).get("did")
        if not did or not isinstance(did, str):
            raise HttpError(400, "did is required")

        scope = (body or {}).get("scope", "doc_type")
        if scope not in {"doc_type", "user", "org"}:
            raise HttpError(400, "Invalid scope: expected 'doc_type', 'user', or 'org'")

        # Safety: host must match configured host
        host, org, user, doc_type = parse_did_web(did)
        expected = getattr(
            settings, "DID_DOMAIN_HOST", "annuairedid-fe.qcdigitalhub.com"
        )
        if host != expected:
            raise HttpError(400, f"Host mismatch: expected {expected}, got {host}")

        # Compute rel path for scope
        paths = relpaths_for_did(did)
        rel_map = {
            "doc_type": paths["doc_type"],
            "user": paths["user"],
            "org": paths["org"],
        }
        rel_path = rel_map[scope]

        # Delete; prune parents only when not removing the org-level directly
        prune = bool((body or {}).get("prune_empty_parents")) and scope != "org"
        try:
            result = remove_published_path(rel_path, prune_empty_parents=prune)
        except ValueError as ve:
            raise HttpError(400, str(ve))

        message = "Removed" if result["removed"] else "Not found"
        return self.create_response(
            message=message,
            data={
                "did": did,
                "scope": scope,
                "org": org,
                "user": user,
                "document_type": doc_type,
                "rel_path": rel_path,
                "abs_path": result["abs_path"],
                "removed": result["removed"],
                "pruned": result.get("pruned", []),
            },
            status_code=200,
        )

    @route.get("/health", auth=None)
    def health_stats(self):
        from orbit import get_watcher_status, get_failed_watchers

        # Get status of all watchers
        status = get_watcher_status()
        # {'cache': {'installed': True, 'error': None, 'disabled': False}, ...}

        # Get only failed watchers
        failed = get_failed_watchers()
        # {'celery': 'ModuleNotFoundError: No module named celery'}

        return self.create_response(
            data={"orbit_watcher_status": status, "orbit_failed_watchers": failed}
        )


# from __future__ import annotations
# from datetime import timedelta
# from typing import Any, Dict, List

# from django.http import JsonResponse
# from django.utils import timezone
# from django.db.models import Count, Q
# from django.db.models.functions import TruncDay
# from ninja_extra import api_controller, route
# from ninja_jwt.authentication import JWTAuth

# from src.dids.models import (
#     DID,
#     DIDDocument,
#     PublishRequest,
#     UploadedPublicKey,
#     Certificate,
# )


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


# `@api_controller`("/superadmin/dids", tags=["Superadmin"], auth=JWTAuth())
# class SuperadminDIDsStatsController:
#     `@route.get`("/stats")
#     def global_stats(self, request, window_days: int = 30):
#         """
#         Global stats across all organizations. SUPERUSER only.
#         """
#         if not getattr(request.user, "is_superuser", False):
#             return JsonResponse({"success": False, "message": "Forbidden"}, status=403)

#         now = timezone.now()
#         since = now - timedelta(days=window_days)

#         did_qs = DID.objects.all()

#         dids_total = did_qs.count()
#         dids_by_status = {
#             row["status"]: row["c"]
#             for row in did_qs.values("status").annotate(c=Count("id"))
#         }

#         docs_draft = DIDDocument.objects.filter(environment="DRAFT").count()
#         docs_prod_active = DIDDocument.objects.filter(
#             environment="PROD", is_active=True
#         ).count()

#         pr_pending = PublishRequest.objects.filter(
#             status=PublishRequest.Status.PENDING
#         ).count()
#         pr_approved = PublishRequest.objects.filter(
#             status=PublishRequest.Status.APPROVED, decided_at__gte=since
#         ).count()
#         pr_rejected = PublishRequest.objects.filter(
#             status=PublishRequest.Status.REJECTED, decided_at__gte=since
#         ).count()

#         keys_active = UploadedPublicKey.objects.filter(is_active=True).count()
#         rotations_last_window = UploadedPublicKey.objects.filter(
#             version__gt=1, created_at__gte=since
#         ).count()

#         cert_count = Certificate.objects.all().count()
#         compliance_rows = (
#             Certificate.objects.all()
#             .values("compliance__status")
#             .annotate(c=Count("id"))
#         )
#         compliance_dist = {
#             (row["compliance__status"] or "UNKNOWN"): row["c"]
#             for row in compliance_rows
#         }

#         dids_by_type = {
#             row["document_type"]: row["c"]
#             for row in did_qs.values("document_type").annotate(c=Count("id"))
#         }
#         prod_active_by_type = {
#             row["did__document_type"]: row["c"]
#             for row in DIDDocument.objects.filter(
#                 environment="PROD", is_active=True
#             )
#             .values("did__document_type")
#             .annotate(c=Count("id"))
#         }
#         by_document_type = []
#         for dt, cnt in dids_by_type.items():
#             by_document_type.append(
#                 {
#                     "document_type": dt,
#                     "dids": cnt,
#                     "prod_active": prod_active_by_type.get(dt, 0),
#                 }
#             )

#         curves_rows = (
#             UploadedPublicKey.objects.all()
#             .values("public_key_jwk__crv")
#             .annotate(c=Count("id"))
#         )
#         by_curve = {
#             (row["public_key_jwk__crv"] or "unknown"): row["c"] for row in curves_rows
#         }

#         purposes_rows = list(UploadedPublicKey.objects.all().values_list("purposes", flat=True))
#         by_purpose = _accumulate_purposes(purposes_rows)

#         published_docs_qs = DIDDocument.objects.filter(
#             environment="PROD", published_at__isnull=False
#         )
#         published_last_window = published_docs_qs.filter(published_at__gte=since).count()
#         published_series = _series(published_docs_qs, "published_at", window_days)

#         rotations_qs = UploadedPublicKey.objects.filter(version__gt=1)
#         rotations_series = _series(rotations_qs, "created_at", window_days)

#         pending_reqs = list(
#             PublishRequest.objects.filter(status=PublishRequest.Status.PENDING)
#             .select_related("did", "requested_by", "did_document", "did__organization")
#             .order_by("-created_at")[:10]
#         )
#         pending_requests = [
#             {
#                 "id": str(pr.id),
#                 "did": pr.did.did,
#                 "version": pr.did_document.version,
#                 "organization_id": str(getattr(pr.did.organization, "id", "")),
#                 "requested_by": getattr(pr.requested_by, "email", None),
#                 "requested_at": pr.created_at.isoformat() if pr.created_at else None,
#             }
#             for pr in pending_reqs
#         ]

#         recent_publishes_qs = (
#             DIDDocument.objects.filter(
#                 environment="PROD", is_active=True, published_at__isnull=False
#             )
#             .select_related("did")
#             .order_by("-published_at")[:5]
#         )
#         recent_publishes = [
#             {
#                 "did": doc.did.did,
#                 "version": doc.version,
#                 "published_at": doc.published_at.isoformat()
#                 if doc.published_at
#                 else None,
#                 "published_relpath": doc.published_relpath,
#             }
#             for doc in recent_publishes_qs
#         ]

#         payload = {
#             "scope": "global",
#             "as_of": now.isoformat(),
#             "window_days": window_days,
#             "totals": {
#                 "dids": dids_total,
#                 "dids_by_status": dids_by_status,
#                 "documents": {"draft": docs_draft, "prod_active": docs_prod_active},
#                 "publish_requests": {
#                     "pending": pr_pending,
#                     "approved_last_window": pr_approved,
#                     "rejected_last_window": pr_rejected,
#                 },
#                 "keys": {
#                     "active_uploaded_keys": keys_active,
#                     "rotations_last_window": rotations_last_window,
#                 },
#                 "certificates": {
#                     "count": cert_count,
#                     "compliance": compliance_dist,
#                 },
#             },
#             "breakdowns": {
#                 "by_document_type": by_document_type,
#                 "by_curve": by_curve,
#                 "by_purpose": by_purpose,
#             },
#             "activity": {
#                 "publish_prod": {"count": published_last_window},
#                 "rotations": {"count": rotations_last_window},
#             },
#             "time_series": {
#                 "published_prod": published_series,
#                 "rotations": rotations_series,
#             },
#             "pending_requests": pending_requests,
#             "top": {"most_recent_publishes": recent_publishes},
#         }
#         return JsonResponse(payload, status=200)