import uuid
import logging

from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone

from ninja_extra import api_controller, route
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth
from ninja import Body

from src.dids.models import PublishRequest
from src.dids.did_registry_api.selectors.publish_requests import list_publish_requests, get_publish_request
from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.did_registry_api.schemas.envelopes import ok, err
from src.dids.did_registry_api.services.publish import publish_to_prod
from src.dids.did_registry_api.notifications.email import send_publish_decision_notification
from src.auditaction.services import audit_action_create
from src.auditaction.models import AuditAction, AuditCategory

logger = logging.getLogger(__name__)

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
    def approve(self, request, pr_id: uuid.UUID, body: dict = Body(None)):
        try:
            pr = get_publish_request(str(pr_id))
        except PublishRequest.DoesNotExist:
            raise HttpError(404, "PublishRequest not found")
    
        if pr.status != PublishRequest.Status.PENDING:
            return err(request, 409, "PUBLISH_REQUEST_NOT_PENDING", path=f"/api/registry/publish-requests/{pr_id}/approve")
    
        # Only org admins of the DID's organization can approve/reject
        if not is_org_admin(request.user, pr.did.organization):
            raise HttpError(403, "Forbidden")
    
        # Decision
        pr.status = PublishRequest.Status.APPROVED
        pr.decided_by = request.user
        pr.decided_at = timezone.now()
        pr.save(update_fields=["status", "decided_by", "decided_at"])
    
        # Perform publish (signing currently disabled → publish as-is)
        url = publish_to_prod(pr.did_document)
    
        # Persist publish audit on the document if the fields exist
        if hasattr(pr.did_document, "published_at") and hasattr(pr.did_document, "published_by"):
            pr.did_document.published_at = timezone.now()
            pr.did_document.published_by = request.user
            pr.did_document.save(update_fields=["published_at", "published_by"])
    
        # Audit decision
        audit_action_create(
            user=request.user,
            action=AuditAction.PUBLISH_REQUEST_APPROVED,
            details={
                "publish_request_id": str(pr.id),
                "did": pr.did.did,
                "version": pr.did_document.version,
                "environment": "PROD",
                "location": url,
            },
            category=AuditCategory.DID,
            organization=pr.did.organization,
            target_type="publish_request",
            target_id=pr.id,
        )
    
        # Send email after commit; log + audit if email fails (does not break API)
        def _send():
            try:
                send_publish_decision_notification(pr)
            except Exception as e:
                logger.exception("Failed to send publish decision email", extra={"publish_request_id": str(pr.id)})
                audit_action_create(
                    user=request.user,
                    action=AuditAction.EMAIL_SEND_FAILED,
                    details={"publish_request_id": str(pr.id), "error": str(e)},
                    category=AuditCategory.DID,
                    organization=pr.did.organization,
                    target_type="publish_request",
                    target_id=pr.id,
                )
        transaction.on_commit(_send)
    
        # Auto-delete request after decision (kept in audit trail)
        pr.delete()
    
        return ok(
            request,
            did_state={"state": "finished", "did": pr.did.did, "environment": "PROD", "location": url},
            did_doc_meta={"versionId": str(pr.did_document.version), "environment": "PROD", "published": True},
            did_reg_meta={"method": "web"},
            status=200
        )

    @route.post("/publish-requests/{pr_id}/reject")
    def reject(self, request, pr_id: uuid.UUID, body: dict = Body(None)):
        try:
            pr = get_publish_request(str(pr_id))
        except PublishRequest.DoesNotExist:
            raise HttpError(404, "PublishRequest not found")
    
        if pr.status != PublishRequest.Status.PENDING:
            return err(request, 409, "PUBLISH_REQUEST_NOT_PENDING", path=f"/api/registry/publish-requests/{pr_id}/reject")
    
        if not is_org_admin(request.user, pr.did.organization):
            raise HttpError(403, "Forbidden")
    
        pr.status = PublishRequest.Status.REJECTED
        pr.decided_by = request.user
        pr.decided_at = timezone.now()
        pr.save(update_fields=["status", "decided_by", "decided_at"])
    
        audit_action_create(
            user=request.user,
            action=AuditAction.PUBLISH_REQUEST_REJECTED,
            details={
                "publish_request_id": str(pr.id),
                "did": pr.did.did,
                "version": pr.did_document.version,
                "environment": "PROD",
                "reason": (body or {}).get("reason"),
            },
            category=AuditCategory.DID,
            organization=pr.did.organization,
            target_type="publish_request",
            target_id=pr.id,
        )
    
        def _send():
            try:
                send_publish_decision_notification(pr)
            except Exception as e:
                logger.exception("Failed to send publish decision email", extra={"publish_request_id": str(pr.id)})
                audit_action_create(
                    user=request.user,
                    action=AuditAction.EMAIL_SEND_FAILED,
                    details={"publish_request_id": str(pr.id), "error": str(e)},
                    category=AuditCategory.DID,
                    organization=pr.did.organization,
                    target_type="publish_request",
                    target_id=pr.id,
                )
        transaction.on_commit(_send)
    
        pr.delete()
    
        return ok(
            request,
            did_state={"state": "finished", "did": pr.did.did, "environment": "PROD", "reason": "rejected"},
            did_doc_meta={"versionId": str(pr.did_document.version), "environment": "PROD", "published": False},
            did_reg_meta={"method": "web"},
            status=200
        )