import json
import os
import uuid
import re
import base64
import tempfile
import subprocess

from django.db import transaction
from django.utils import timezone
from django.conf import settings

from ninja.errors import HttpError
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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


KNOWN_JOSE_CURVES = {"P-256", "P-384", "P-521"}

class JavaFallbackError(Exception):
    pass

def jwk_from_der_via_java(der_bytes: bytes) :
    """
    Write DER bytes to a temp file and invoke the Java JAR to extract a JWK.
    Returns (jwk, compliance).
    Compliance: WARN for known curves (explicit params); NON_COMPLIANT when crv is unknown.
    """
    jar_path = getattr(settings, "CERT_JAVA_JAR", "/app/bin/ecdsa-extractor.jar")
    timeout_s = int(getattr(settings, "CERT_JAVA_TIMEOUT_S", 10))
    if not os.path.isfile(jar_path):
        raise JavaFallbackError(f"Java JAR not found at {jar_path}")

    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(prefix="cert_", suffix=".der", delete=False)
        tmp.write(der_bytes)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        if tmp:
            tmp.close()

    try:
        # Limit memory a bit; rely on system default if not needed
        cmd = ["java", "-Xmx64m", "-jar", jar_path, tmp_path]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
        if proc.returncode != 0:
            raise JavaFallbackError(proc.stderr.strip() or "Java extractor failed")

        try:
            jwk = json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError as e:
            raise JavaFallbackError(f"Invalid JSON from Java extractor: {e}") from e

        crv = (jwk or {}).get("crv")
        if crv in KNOWN_JOSE_CURVES:
            compliance = {
                "status": "WARN",
                "reason": "EXPLICIT_EC_PARAMS",
                "ec_params_encoding": "explicit",
                "detected_curve": crv,
                "jose_crv": crv,
            }
        else:
            compliance = {
                "status": "NON_COMPLIANT",
                "reason": "UNKNOWN_CURVE_EXPLICIT_PARAMS",
                "ec_params_encoding": "explicit",
                "detected_curve": None,
                "jose_crv": crv or "unknown",
            }

        return jwk, compliance

    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

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


def _native_jwk_and_compliance(cert: x509.Certificate):
    pub = cert.public_key()
    jwk = jwk_from_public_key(pub)
    # Compliance for native path
    if isinstance(pub, rsa.RSAPublicKey):
        return jwk, {"status": "OK", "reason": None, "ec_params_encoding": None, "detected_curve": None,
                     "jose_crv": None, }
    if isinstance(pub, ec.EllipticCurvePublicKey):
        name = getattr(pub.curve, "name", None)
        jose_crv = jwk.get("crv")
        if jose_crv in ("P-256", "P-384", "P-521"):
            return jwk, {"status": "OK", "reason": None, "ec_params_encoding": "named", "detected_curve": name,
                         "jose_crv": jose_crv,}
        return jwk, {"status": "NON_COMPLIANT", "reason": "UNKNOWN_CURVE_NAMED", "ec_params_encoding": "named",
                     "detected_curve": name, "jose_crv": jose_crv,}
    raise ValueError("Unsupported public key type")

def _is_explicit_params_error(e: Exception) -> bool:
    """Check if error is related to explicit EC parameters"""
    msg = str(e).lower()
    return any(
        keyword in msg
        for keyword in [
            "explicit",
            "parameter",
            "unnamed curve",
            "explicit curves are not supported",
            "explicit ec parameters",
        ]
    )


def parse_and_normalize_certificate(*, file_bytes: bytes, fmt: str, password: str | None):
    """
    Parse certificate and extract JWK with compliance information.
    Falls back to Java extractor for certificates with explicit EC parameters.
    """
    java_fallback_enabled = getattr(settings, "CERT_JAVA_FALLBACK_ENABLED", True)

    # First attempt: Try to load with cryptography library
    try:
        cert = load_x509(file_bytes, fmt, password=password)
        fingerprint = compute_fingerprint(cert)
        jwk, compliance = _native_jwk_and_compliance(cert)
        return jwk, fingerprint, compliance

    except Exception as load_error:
        # If Java fallback is disabled, re-raise immediately
        if not java_fallback_enabled:
            raise

        # Check if this is an explicit params error
        if not _is_explicit_params_error(load_error):
            # Not an explicit params issue, re-raise
            raise

        # Java fallback path for explicit parameters
        # We need to get the raw DER bytes
        effective_fmt = detect_effective_format(fmt, file_bytes)

        if effective_fmt == "PEM":
            # Convert PEM to DER for Java processing
            try:
                # Try to extract DER from PEM (this might fail for explicit params too)
                from cryptography.hazmat.primitives.serialization import load_pem_x509_certificate
                # Use a more lenient loader or just pass PEM to Java
                # For now, convert PEM to DER manually

                # Extract base64 content between BEGIN/END CERTIFICATE
                pem_str = file_bytes.decode('ascii')
                match = re.search(
                    r'-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----',
                    pem_str,
                    re.DOTALL
                )
                if not match:
                    raise ValueError("Invalid PEM format")

                der_bytes = base64.b64decode(match.group(1))
            except Exception:
                # If conversion fails, raise the original error
                raise load_error
        else:
            # Already DER format
            der_bytes = file_bytes

        # Call Java fallback
        try:
            jwk, compliance = jwk_from_der_via_java(der_bytes)

            # We need fingerprint, but we can't compute it from cert object
            # Compute it from DER bytes directly
            import hashlib
            fingerprint = hashlib.sha256(der_bytes).hexdigest().upper()

            return jwk, fingerprint, compliance

        except Exception as java_error:
            # Java fallback failed, raise original error with context
            raise ValueError(
                f"Certificate parsing failed (native: {load_error}; java: {java_error})"
            ) from load_error



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
