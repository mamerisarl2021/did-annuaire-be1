# Services (hash JCS, publish atomique, helpers)
from __future__ import annotations
import os
import json
import hashlib
import tempfile
import pathlib
from typing import Tuple
from django.db import transaction
from src.dids.utils.validators import validate_did_document
from collections import OrderedDict

PREFERRED_ORDER = [
    "@context",
    "id",
    "controller",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
    "service",
    "proof",
    "deactivated",
]


def order_did_document(doc: dict) -> dict:
    # construct an OrderedDict respecting the preferred order; append unknown keys at the end
    out = OrderedDict()
    for k in PREFERRED_ORDER:
        if k in doc:
            out[k] = doc[k]
    for k, v in doc.items():
        if k not in out:
            out[k] = v
    return out


try:
    import rfc8785  # JSON Canonicalization Scheme
except ImportError:
    rfc8785 = None

DIDS_ROOT = "/var/www/dids/.well-known"


def build_host() -> str:
    return os.environ.get("DID_DOMAIN_HOST", "annuairedid-fe.qcdigitalhub.com")


def build_did(org_slug: str, user_slug: str, doc_type: str) -> str:
    return f"did:web:{build_host()}:{org_slug}:{user_slug}:{doc_type}"


def build_relpath(env: str, org_slug: str, user_slug: str, doc_type: str) -> str:
    base = f"{org_slug}/{user_slug}/{doc_type}/did.json"
    return f"preprod/{base}" if env == "PREPROD" else base


def jcs_canonical_bytes(document: dict) -> bytes:
    if rfc8785:
        out = rfc8785.dumps(document)
        # rfc8785.dumps() can return str (some versions) or bytes (others)
        if isinstance(out, (bytes, bytearray)):
            return bytes(out)
        return out.encode("utf-8")
    # Fallback (non RFC): deterministic ordering
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(abs_path: str, data: bytes) -> Tuple[str, str | None]:
    path = pathlib.Path(abs_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, abs_path)
    return sha256_hex(data), None  # (file_sha256, etag)


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


def draft_fill_hash(did_document_model) -> None:
    b = jcs_canonical_bytes(did_document_model.document)
    did_document_model.canonical_sha256 = sha256_hex(b)
    did_document_model.save(update_fields=["canonical_sha256"])


@transaction.atomic
def activate_single_env(did_obj, environment: str, new_doc_model) -> None:
    did_obj.documents.filter(environment=environment, is_active=True).exclude(
        pk=new_doc_model.pk
    ).update(is_active=False)
    new_doc_model.is_active = True
    new_doc_model.save(update_fields=["is_active"])


def publish_preprod(did_document_model) -> str:
    validate_did_document(did_document_model.document)
    did = did_document_model.did
    org_slug = derive_org_slug(did.organization)
    user_slug = derive_user_slug(did.owner)
    expected = build_did(org_slug, user_slug, did.document_type)
    assert did_document_model.document.get("id") == expected, "DID Document id mismatch"
    rel = build_relpath("PREPROD", org_slug, user_slug, did.document_type)
    abs_path = os.path.join(DIDS_ROOT, rel)
    ordered = order_did_document(did_document_model.document)
    payload = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    file_sha, etag = atomic_write(abs_path, payload)
    did_document_model.file_sha256 = file_sha
    did_document_model.file_etag = etag
    did_document_model.published_relpath = rel
    did_document_model.environment = "PREPROD"
    did_document_model.save(
        update_fields=["file_sha256", "file_etag", "published_relpath", "environment"]
    )
    activate_single_env(did, "PREPROD", did_document_model)
    return f"https://{build_host()}/{rel}"


def publish_prod(did_document_model) -> str:
    validate_did_document(did_document_model.document)
    did = did_document_model.did
    org_slug = derive_org_slug(did.organization)
    user_slug = derive_user_slug(did.owner)
    expected = build_did(org_slug, user_slug, did.document_type)
    assert did_document_model.document.get("id") == expected, "DID Document id mismatch"
    rel = build_relpath("PROD", org_slug, user_slug, did.document_type)
    abs_path = os.path.join(DIDS_ROOT, rel)
    ordered = order_did_document(did_document_model.document)
    payload = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    file_sha, etag = atomic_write(abs_path, payload)
    did_document_model.file_sha256 = file_sha
    did_document_model.file_etag = etag
    did_document_model.published_relpath = rel
    did_document_model.environment = "PROD"
    did_document_model.save(
        update_fields=["file_sha256", "file_etag", "published_relpath", "environment"]
    )
    activate_single_env(did, "PROD", did_document_model)
    return f"https://{build_host()}/{rel}"


def deactivate_did(did_obj) -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_obj.did,
        "deactivated": True,
    }
