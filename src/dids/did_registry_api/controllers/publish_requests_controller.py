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
from src.dids.did_registry_api.selectors.publish_requests import list_publish_requests
from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.did_registry_api.schemas.envelopes import ok, err
from src.dids.services import publish_request_approve, publish_request_reject
from src.dids.did_registry_api.notifications.email import (
    send_publish_decision_notification,
)
from src.auditaction.services import audit_action_create
from src.auditaction.models import AuditAction, AuditCategory

logger = logging.getLogger(__name__)


class PublishRequestError(Exception):
    pass


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class PublishRequestsController:
    @route.get("/publish-requests")
    def list_requests(
        self,
        request,
        org_id: str,
        status: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[dict]:
        # Load one request to discover org, else 404 later when none
        qs = list_publish_requests(org_id, status, offset, limit)
        # Minimal authZ: requires ORG_ADMIN of org_id (controller-side check)
        # For strictness, when empty list we cannot infer org; rely on caller being ORG_ADMIN (front contrôlé).
        if qs:
            org = qs[0].did.organization
            if not is_org_admin(request.user, org):
                raise HttpError(403, "Forbidden")
        return [
            {
                "id": pr.id,
                "did": pr.did.did,
                "version": pr.did_document.version,
                "environment": pr.environment,
                "status": pr.status,
                "requested_by": getattr(pr.requested_by, "email", None),
                "decided_by": getattr(pr.decided_by, "email", None)
                if pr.decided_by
                else None,
                "decided_at": pr.decided_at.isoformat() if pr.decided_at else None,
                "note": pr.note or None,
            }
            for pr in qs
        ]

    @route.post("/publish-requests/{pr_id}/approve")
    def approve(self, request, pr_id: uuid.UUID):
        result = publish_request_approve(pr_id=pr_id, decided_by=request.user)

        return ok(
            request,
            did_state={
                "state": "finished",
                "did": result["did"],
                "environment": "PROD",
                "location": result["url"],
            },
            did_doc_meta={
                "versionId": str(result["version"]),
                "environment": "PROD",
                "published": True,
            },
            did_reg_meta={"method": "web"},
            status=200,
        )

    @route.post("/publish-requests/{pr_id}/reject")
    def reject(self, request, pr_id: uuid.UUID, body: dict = Body(None)):
        result = publish_request_reject(
            pr_id=pr_id, decided_by=request.user, reason=(body or {}).get("reason")
        )

        return ok(
            request,
            did_state={
                "state": "finished",
                "did": result["did"],
                "environment": "DRAFT",
                "reason": "rejected",
            },
            did_doc_meta={
                "versionId": str(result["version"]),
                "environment": "DRAFT",
                "published": False,
            },
            did_reg_meta={"method": "web"},
            status=200,
        )
