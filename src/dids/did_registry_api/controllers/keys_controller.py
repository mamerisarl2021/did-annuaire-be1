from django.db.models import Max
from django.shortcuts import get_object_or_404
from jsonschema import ValidationError

from ninja import Body
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth

from src.dids.did_registry_api.selectors.did_documents import latest_draft, active_prod
from src.dids.models import Certificate, UploadedPublicKey, DIDDocument, DID
from src.dids.did_registry_api.selectors.dids import get_did_or_404
from src.dids.did_registry_api.selectors.keys import list_key_versions
from src.dids.did_registry_api.policies.access import can_manage_did
from src.dids.did_document_compiler.builders import build_did_document_from_db
from src.dids.utils.validators import validate_did_document
from src.dids.proof_crypto_engine.canonical.jcs import dumps_bytes, sha256_hex
from src.dids.did_registry_api.schemas.envelopes import ok, err
from src.dids.services import bind_doc_to_keys
from src.dids.did_registry_api.selectors.keys import latest_key_versions


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class KeysController:
    @route.get("/dids/{did}/keys")
    def list_keys(self, request, did: str) -> list[dict]:
        did_obj = get_did_or_404(did)
        #if not can_manage_did(request.user, did_obj):
        #    raise HttpError(403, "Forbidden")
        return list_key_versions(did_obj)

    @route.post("/dids/{did}/keys/rotate")
    def rotate_key(self, request, did: str, body: dict = Body(...)):
        """
        Body: { certificate_id: UUID, purposes?: [], key_id?: str (ignored if provided) }
        Backend infers the stable key_id from current verificationMethod.id (latest DRAFT else active PROD).
        """
        did_obj = get_did_or_404(did)
        if not can_manage_did(request.user, did_obj):
            raise HttpError(403, "Forbidden")

        certificate_id = body.get("certificate_id")
        purposes = body.get("purposes")
        if not certificate_id:
            return err(
                request,
                400,
                "certificate_id is required",
                path=f"/api/registry/dids/{did}/keys/rotate",
            )

        cert = get_object_or_404(
            Certificate,
            pk=certificate_id,
            organization=did_obj.organization,
            owner=request.user,
        )

        if did_obj.status == DID.DIDStatus.DEACTIVATED:
            return err(
                request,
                409,
                "DID_DEACTIVATED",
                path=f"/api/registry/dids/{did}/keys/rotate",
            )

        # Infer key_id from current doc (single-VM required)
        ref_doc = (
            latest_draft(did_obj)
            or active_prod(did_obj)
            or did_obj.documents.order_by("-version").first()
        )
        if not ref_doc:
            return err(
                request,
                404,
                "No existing document to infer key_id from",
                path=f"/api/registry/dids/{did}/keys/rotate",
            )

        vms = ref_doc.document.get("verificationMethod") or []
        if not isinstance(vms, list) or len(vms) != 1:
            return err(
                request,
                400,
                "SINGLE_VM_REQUIRED: cannot infer key_id when verificationMethod!=1",
                path=f"/api/registry/dids/{did}/keys/rotate",
            )

        vm_id = vms[0].get("id") or ""
        key_id = vm_id.split("#", 1)[1] if "#" in vm_id else vm_id
        if not key_id:
            return err(
                request,
                400,
                "CANNOT_INFER_KEY_ID from verificationMethod.id",
                path=f"/api/registry/dids/{did}/keys/rotate",
            )

        # Bump key material version for inferred key_id
        latest_ver = (
            (
                UploadedPublicKey.objects.filter(did=did_obj, key_id=key_id).aggregate(
                    m=Max("version")
                )["m"]
            )
            or 0
        )
        new_version = latest_ver + 1

        UploadedPublicKey.objects.create(
            did=did_obj,
            key_id=key_id,
            key_type=UploadedPublicKey.KeyType.JSON_WEB_KEY_2020,
            version=new_version,
            certificate=cert,
            public_key_jwk=cert.extracted_jwk,
            public_key_jwk_snapshot=cert.extracted_jwk,
            purposes=purposes or [],
            is_active=True,
        )

        # Rebuild DID Document → new DRAFT
        try:
            _did_str, document, _versions_map = build_did_document_from_db(did_obj)
            validate_did_document(document)
        except ValidationError as ve:
            return err(
                request, 400, str(ve), path=f"/api/registry/dids/{did}/keys/rotate"
            )
        except ValueError as ve:
            return err(
                request, 400, str(ve), path=f"/api/registry/dids/{did}/keys/rotate"
            )

        next_version = (
            (
                DIDDocument.objects.filter(did=did_obj).aggregate(Max("version"))[
                    "version__max"
                ]
            )
            or 0
        ) + 1
        did_doc = DIDDocument.objects.create(
            did=did_obj,
            version=next_version,
            document=document,
            environment="DRAFT",
            is_active=False,
        )

        # Canonical hash + bindings
        canon = dumps_bytes(document)
        digest = sha256_hex(canon)
        if hasattr(did_doc, "canonical_sha256"):
            did_doc.canonical_sha256 = digest
            did_doc.save(update_fields=["canonical_sha256"])

        bind_doc_to_keys(did_doc, latest_key_versions(did_obj))

        return ok(
            request,
            did_state={
                "state": "update",
                "did": did_obj.did,
                "didDocument": document,
                "environment": "DRAFT",
                "version": did_doc.version,
            },
            did_doc_meta={
                "versionId": str(did_doc.version),
                "environment": "DRAFT",
                "published": False,
            },
            did_reg_meta={"method": "web"},
            status=200,
        )
