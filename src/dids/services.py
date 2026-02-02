import os
import uuid

from django.db import transaction
from django.utils import timezone

from ninja.errors import HttpError

from src.dids.models import UploadedPublicKey, DidDocumentKeyBinding, PublishRequest
from src.auditaction.models import AuditAction, AuditCategory
from src.auditaction.services import audit_action_create
from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.did_registry_api.services.publish import publish_to_prod
from src.dids.did_registry_api.notifications.email import (
    send_publish_decision_notification,
)
from src.users.models import User
from src.dids.did_registry_api.schemas.envelopes import err

from .selectors import get_publish_request_for_update


def build_host() -> str:
    return os.environ.get("DID_DOMAIN_HOST", "annuairedid-fe.qcdigitalhub.com")


def build_did(org_slug: str, user_slug: str, doc_type: str) -> str:
    return f"did:web:{build_host()}:{org_slug}:{user_slug}:{doc_type}"


def derive_org_slug(organization) -> str:
    for attr in ("namespace", "slug"):
        val = getattr(organization, attr, None)
        if val:
            return str(val)
    return str(organization.pk)


def derive_user_slug(user) -> str:
    for attr in ("slug", "username"):
        val = getattr(user, attr, None)
        if val:
            return str(val)
    return str(user.pk)


def deactivate_did(did_obj) -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_obj.did,
        "deactivated": True,
    }


def latest_key_versions_for_did(did_obj) -> dict[str, UploadedPublicKey]:
    """
    Return a dict key_id -> latest active UploadedPublicKey for this DID.
    """
    qs = UploadedPublicKey.objects.filter(did=did_obj, is_active=True).order_by(
        "key_id", "-version"
    )
    out: dict[str, UploadedPublicKey] = {}
    for upk in qs:
        if upk.key_id not in out:
            out[upk.key_id] = upk
    return out


@transaction.atomic
def bind_doc_to_keys(did_document_model, key_map: dict[str, UploadedPublicKey]):
    """
    Persist bindings (document -> the concrete key versions used).
    """
    # Clear existing bindings for safety (re-build)
    did_document_model.key_bindings.all().delete()
    for key_id, upk in key_map.items():
        DidDocumentKeyBinding.objects.create(
            did_document=did_document_model,
            uploaded_public_key=upk,
            purposes_snapshot=upk.purposes,
        )


@transaction.atomic
def publish_request_approve(pr_id: uuid.UUID, decided_by: User):
    """
    Approves and processes a publish request within a single atomic transaction to prevent race condition
    """
    try:
        pr = get_publish_request_for_update(str(pr_id))
    except PublishRequest.DoesNotExist:
        raise HttpError(404, "PUBLISH_REQUEST_NOT_FOUND")

    if pr.status != PublishRequest.Status.PENDING:
        raise HttpError(409, "PUBLISH_REQUEST_NOT_PENDING")

    if not is_org_admin(decided_by, pr.did.organization):
        raise HttpError(403, "Forbidden")

    pr.status = PublishRequest.Status.APPROVED
    pr.decided_by = decided_by
    pr.decided_at = timezone.now()
    pr.save(update_fields=["status", "decided_by", "decided_at"])

    url = publish_to_prod(pr.did_document)

    if hasattr(pr.did_document, "published_at") and hasattr(
        pr.did_document, "published_by"
    ):
        pr.did_document.published_at = timezone.now()
        pr.did_document.published_by = decided_by
        pr.did_document.save(update_fields=["published_at", "published_by"])

        audit_action_create(
            user=decided_by,
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

        transaction.on_commit(lambda: send_publish_decision_notification(pr))

        response_data = {
            "did": pr.did.did,
            "version": pr.did_document.version,
        }

        # pr.delete()

        return response_data


@transaction.atomic
def publish_request_reject(pr_id: uuid.UUID, decided_by: User, reason: str):
    """
    Refuse and processes a publish request within a single atomic transaction to prevent race condition
    """
    try:
        pr = get_publish_request_for_update(str(pr_id))
    except PublishRequest.DoesNotExist:
        raise HttpError(404, "PUBLISH_REQUEST_NOT_FOUND")

    if pr.status != PublishRequest.Status.PENDING:
        raise HttpError(409, "PUBLISH_REQUEST_NOT_PENDING")

    if not is_org_admin(decided_by, pr.did.organization):
        raise HttpError(403, "Forbidden")

    pr.status = PublishRequest.Status.REJECTED
    pr.decided_by = decided_by
    pr.decided_at = timezone.now()
    pr.save(update_fields=["status", "decided_by", "decided_at"])

    audit_action_create(
        user=decided_by,
        action=AuditAction.PUBLISH_REQUEST_REJECTED,
        details={
            "publish_request_id": str(pr.id),
            "did": pr.did.did,
            "version": pr.did_document.version,
            "environment": "PROD",
            "reason": reason,
        },
        category=AuditCategory.DID,
        organization=pr.did.organization,
        target_type="publish_request",
        target_id=pr.id,
    )

    transaction.on_commit(lambda: send_publish_decision_notification(pr))

    response_data = {
        "url": url,
        "did": pr.did.did,
        "version": pr.did_document.version,
    }

    # pr.delete()

    return response_data
