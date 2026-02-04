import json
import os
import uuid

from django.db import transaction
from django.utils import timezone

from ninja.errors import HttpError

from src.dids.models import UploadedPublicKey, DidDocumentKeyBinding, PublishRequest, Certificate, DIDDocument, DID
from src.auditaction.models import AuditAction, AuditCategory
from src.auditaction.services import audit_action_create
from src.dids.did_registry_api.policies.access import is_org_admin
from src.dids.did_registry_api.notifications.email import (
    send_publish_decision_notification,
)
from src.users.models import User
from .did_document_compiler.ordering import order_did_document
from .proof_crypto_engine.certs.jwk_normalize import jwk_from_public_key
from .proof_crypto_engine.certs.loaders import load_x509, compute_fingerprint
from .publishing.fs import atomic_write
from .publishing.paths import build_relpath

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

@transaction.atomic
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
        "did": pr.did.did,
        "version": pr.did_document.version,
    }

    # pr.delete()

    return response_data

def detect_effective_format(fmt: str, data: bytes) -> str:
    f = (fmt or "").upper()
    if f in {"CRT", "AUTO"}:
        return "PEM" if (b"-----BEGIN" in data and b"-----END" in data) else "DER"
    return f


def parse_and_normalize_certificate(*, file_bytes: bytes, fmt: str, password: str | None):
    cert = load_x509(file_bytes, fmt, password=password)
    jwk = jwk_from_public_key(cert.public_key())
    fingerprint = compute_fingerprint(cert)
    return jwk, fingerprint

@transaction.atomic
def upsert_certificate(*, owner, organization, file_obj, fmt: str, jwk: dict, fingerprint: str, ) -> tuple[
    Certificate, bool]:
    """
    Create or reuse a certificate by (organization, fingerprint).
    Returns (cert, created).
    """
    existing = (
        Certificate.objects
        .filter(organization=organization, fingerprint=fingerprint)
        .first()
    )
    if existing:
        return existing, False

    cert = Certificate.objects.create(
        owner=owner,
        organization=organization,
        file=file_obj,
        format=fmt,
        extracted_jwk=jwk,
        fingerprint=fingerprint,
    )
    return cert, True



@transaction.atomic
def activate_prod(did_obj, new_doc_model: DIDDocument) -> None:
    did_obj.documents.filter(environment="PROD", is_active=True).exclude(
        pk=new_doc_model.pk
    ).update(is_active=False)
    new_doc_model.is_active = True
    new_doc_model.save(update_fields=["is_active"])

@transaction.atomic
def _sync_did_status_after_publish(doc: DIDDocument) -> None:
    """
    When a PROD document is published, update the parent DID.status:
      - deactivated:true → DEACTIVATED
      - else → ACTIVE
    """
    if doc.environment != "PROD":
        return
    payload = doc.document or {}
    is_deactivated = bool(isinstance(payload, dict) and payload.get("deactivated"))
    new_status = DID.DIDStatus.DEACTIVATED if is_deactivated else DID.DIDStatus.ACTIVE
    if doc.did.status != new_status:
        doc.did.status = new_status
        doc.did.save(update_fields=["status"])

def publish_to_prod(doc_model: DIDDocument) -> str:
    """
    - write did.json to DIDS_ROOT
    - flip is_active flags (this one True; others False) for (did, 'PROD')
    - set published_relpath/file_sha256/file_etag/published_at/published_by, etc.
    """
    did = doc_model.did
    org = (
        getattr(did.organization, "slug", None)
        or getattr(did.organization, "namespace", None)
        or str(did.organization_id)
    )
    user = (
        getattr(did.owner, "slug", None)
        or getattr(did.owner, "username", None)
        or str(did.owner_id)
    )
    ordered = order_did_document(doc_model.document)
    payload = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    rel = build_relpath(org, user, did.document_type)
    file_sha, etag = atomic_write(rel, payload)
    doc_model.file_sha256 = file_sha
    doc_model.file_etag = etag
    doc_model.published_relpath = rel
    doc_model.environment = "PROD"
    doc_model.save(
        update_fields=["file_sha256", "file_etag", "published_relpath", "environment"]
    )
    activate_prod(did, doc_model)
    _sync_did_status_after_publish(doc_model)
    return f"https://{build_host()}/{rel}"