import os
from django.db import transaction

from src.dids.models import UploadedPublicKey, DidDocumentKeyBinding

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
    return {"@context": ["https://www.w3.org/ns/did/v1"], "id": did_obj.did, "deactivated": True}

def latest_key_versions_for_did(did_obj) -> dict[str, UploadedPublicKey]:
    """
    Return a dict key_id -> latest active UploadedPublicKey for this DID.
    """
    qs = (UploadedPublicKey.objects
          .filter(did=did_obj, is_active=True)
          .order_by('key_id', '-version'))
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

