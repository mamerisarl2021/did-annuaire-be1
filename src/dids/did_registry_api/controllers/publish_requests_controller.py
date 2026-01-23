from ninja_extra import api_controller, route
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from django.utils import timezone as dj_tz
from ninja_jwt.authentication import JWTAuth

from src.dids.models import PublishRequest
from src.dids.did_registry_api.selectors.publish_requests import list_publish_requests, get_publish_request
from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.did_registry_api.schemas.envelopes import ok
from src.dids.did_registry_api.services.publish import publish_to_prod
from src.dids.did_registry_api.notifications.email import send_publish_decision_notification


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class PublishRequestsController:

    @route.get("/publish-requests")
    def list_requests(self, request, org_id: str, status: str | None = None, offset: int = 0, limit: int = 50) -> list[dict]:
        # Load one request to discover org, else 404 later when none
        qs = list_publish_requests(org_id, status, offset, limit)
        # Minimal authZ: requires ORG_ADMIN of org_id (controller-side check)
        # For strictness, when empty list we cannot infer org; rely on caller being ORG_ADMIN (front contrôlé).
        if qs:
            org = qs[0].did.organization
            if not is_org_admin(request.user, org):
                raise HttpError(403, "Forbidden")
        return [{
            "id": pr.id,
            "did": pr.did.did,
            "version": pr.did_document.version,
            "environment": pr.environment,
            "status": pr.status,
            "requested_by": getattr(pr.requested_by, "email", None),
            "decided_by": getattr(pr.decided_by, "email", None) if pr.decided_by else None,
            "decided_at": pr.decided_at.isoformat() if pr.decided_at else None,
            "note": pr.note or None
        } for pr in qs]

    @route.post("/publish-requests/{pr_id}/approve")
    def approve(self, request, pr_id: str, note: str | None = None):
        pr = get_publish_request(pr_id)
        org = pr.did.organization
        if not is_org_admin(request.user, org):
            raise HttpError(403, "Forbidden")
        if pr.status != PublishRequest.Status.PENDING:
            raise HttpError(400, "Request is not pending")
        pr.status = PublishRequest.Status.APPROVED
        pr.decided_by = request.user
        pr.decided_at = dj_tz.now()
        pr.note = note or pr.note
        pr.save(update_fields=["status", "decided_by", "decided_at", "note"])

        send_publish_decision_notification(pr)
        url = publish_to_prod(pr.did_document, "PROD")
        return ok(request,
                  did_state={"state": "finished", "did": pr.did.did, "environment": "PROD", "location": url},
                  did_doc_meta={"versionId": str(pr.did_document.version), "environment": "PROD", "published": True},
                  did_reg_meta={"method": "web"},
                  status=200)

    @route.post("/publish-requests/{pr_id}/reject")
    def reject(self, request, pr_id: str, note: str = None):
        pr = get_publish_request(pr_id)
        org = pr.did.organization
        if not is_org_admin(request.user, org):
            raise HttpError(403, "Forbidden")
        if pr.status != PublishRequest.Status.PENDING:
            raise HttpError(400, "Request is not pending")
        pr.status = PublishRequest.Status.REJECTED
        pr.decided_by = request.user
        pr.decided_at = dj_tz.now()
        pr.note = note or pr.note
        pr.save(update_fields=["status", "decided_by", "decided_at", "note"])

        send_publish_decision_notification(pr)
        return ok(request,
                  did_state={"state": "rejected", "did": pr.did.did, "environment": "PROD"},
                  did_doc_meta={"versionId": str(pr.did_document.version), "environment": "PROD", "published": False},
                  did_reg_meta={"method": "web"},
                  status=200)
