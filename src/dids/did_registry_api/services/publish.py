import json
from django.db import transaction
from src.dids.did_document_compiler.ordering import order_did_document
from src.dids.publishing.paths import build_relpath, build_host
from src.dids.publishing.fs import atomic_write
from src.dids.models import DIDDocument


@transaction.atomic
def activate_prod(did_obj, new_doc_model: DIDDocument) -> None:
    did_obj.documents.filter(environment="PROD", is_active=True).exclude(
        pk=new_doc_model.pk
    ).update(is_active=False)
    new_doc_model.is_active = True
    new_doc_model.save(update_fields=["is_active"])


def publish_to_prod(doc_model: DIDDocument) -> str:
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
    return f"https://{build_host()}/{rel}"
