from django.shortcuts import get_object_or_404
from ninja.errors import HttpError

from src.dids.utils.ids import generate_key_id
from src.organizations.models import Organization
from src.dids.models import Certificate
from src.dids.did_document_compiler.builders import build_did_and_document
from src.dids.utils.validators import validate_did_document  # adapte si autre chemin
from src.dids.proof_crypto_engine.canonical.jcs import dumps_bytes, sha256_hex


def preview_single(
    request_user,
    organization_id: str,
    document_type: str,
    certificate_id: str,
    purposes: list[str] | None,
) -> dict:
    org = get_object_or_404(Organization, pk=organization_id)
    owner = request_user
    cert = get_object_or_404(Certificate, pk=certificate_id, organization=org)

    # Backend-generated key id for preview
    key_id = generate_key_id()

    try:
        did_str, document = build_did_and_document(
            organization=org,
            owner=owner,
            document_type=document_type,
            jwk=cert.extracted_jwk,
            key_id=key_id,
            purposes=purposes if purposes not in (None, []) else None,
            services=None,
        )
    except ValueError as e:
        raise HttpError(400, str(e))

    # Validate + canonical hash
    validate_did_document(document)
    canon = dumps_bytes(document)
    digest = sha256_hex(canon)

    return {
        "did": did_str,
        "document": document,
        "canonical_sha256": digest,
    }
