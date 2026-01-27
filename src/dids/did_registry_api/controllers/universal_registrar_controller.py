from django.db import transaction
from django.db.models import Max
from django.http import JsonResponse
from django.utils import timezone

from jsonschema import ValidationError

from ninja import Body
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from ninja_jwt.authentication import JWTAuth

from src.dids.did_registry_api.services.publish import publish_to_prod
from src.dids.models import DID, DIDDocument
from src.dids.did_registry_api.policies.access import can_manage_did
from src.dids.did_document_compiler.builders import build_did_document_from_db
from src.dids.services import deactivate_did
from src.dids.utils.validators import validate_did_document, verify_or_raise
from src.dids.proof_crypto_engine.canonical.jcs import dumps_bytes, sha256_hex
from src.dids.did_registry_api.schemas.envelopes import ok, err
from src.dids.services import bind_doc_to_keys
from src.dids.did_registry_api.selectors.keys import latest_key_versions



@api_controller("/universal-registrar", tags=["DID Universal Registrar"], auth=JWTAuth())
class UniversalRegistrarController:
    @route.post("/update")
    def update(self, request, body: dict = Body(...)):
        """
        Body minimal: { did: string }
        Owner-only. Recompose from current active keys and create a new DRAFT version (n+1).
        """
        did_str = body.get("did")
        if not did_str:
            raise HttpError(400, "did is required")
        did_obj = get_object_or_404(DID, did=did_str)

        if not can_manage_did(request.user, did_obj):
            raise HttpError(403, "Only the DID owner can update DID properties")

        # Rebuild from DB keys (single VM policy is enforced in builder)
        try:
            did_out, document, _vers = build_did_document_from_db(did_obj)
            validate_did_document(document)
        except ValidationError as ve:
            return err(request, 400, str(ve), path="/universal-registrar/update")
        except ValueError as ve:
            return err(request, 400, str(ve), path="/universal-registrar/update")

        # Enforcement single-VM
        vms = document.get("verificationMethod") or []
        if not isinstance(vms, list) or len(vms) != 1:
            raise HttpError(400, "Exactly one verificationMethod is required by platform policy.")

        validate_did_document(document)

        next_version = ((DIDDocument.objects.filter(did=did_obj).aggregate(Max('version'))['version__max']) or 0) + 1
        did_doc = DIDDocument.objects.create(did=did_obj, version=next_version, document=document, environment="DRAFT", is_active=False)

        canon = dumps_bytes(document); digest = sha256_hex(canon)
        if hasattr(did_doc, "canonical_sha256"):
            did_doc.canonical_sha256 = digest
            did_doc.save(update_fields=["canonical_sha256"])

        # Audit trail: bind the document to the currently active key version(s)
        bind_doc_to_keys(did_doc, latest_key_versions(did_obj))

        return ok(request,
                  did_state={"state": "update", "did": did_out, "didDocument": document,
                             "environment": "DRAFT", "version": did_doc.version},
                  did_doc_meta={"versionId": str(did_doc.version), "environment": "DRAFT", "published": False, "canonical_sha256": digest},
                  did_reg_meta={"method": "web"},
                  status=200)

    @route.post("/deactivate")
    @transaction.atomic
    def deactivate(self, request, body: dict = Body(...)):
        """
        Body: { did: string, otp_code: string }
        Owner-only. Publishes a minimal {"deactivated":} DID Document in PROD.
        """
        did_str = body.get("did")
        if not did_str:
            raise HttpError(400, "did is required")
        
        verify_or_raise(request.user, body.get("otp_code"), scope="deactivate")    
        
        did_obj = get_object_or_404(DID, did=did_str)

        if not can_manage_did(request.user, did_obj):
            raise HttpError(403, "Only the DID owner can deactivate the DID")

        # Document minimal deactivation
        doc = deactivate_did(did_obj)
        # Crée une nouvelle version DRAFT, puis publie en PROD
        next_version = ((DIDDocument.objects.filter(did=did_obj).aggregate(Max('version'))['version__max']) or 0) + 1
        did_doc = DIDDocument.objects.create(did=did_obj, version=next_version, document=doc, environment="DRAFT",
                                             is_active=False)

        url = publish_to_prod(did_doc)
        if hasattr(doc, "published_at") and hasattr(doc, "published_by"):
                    did_doc.published_at = timezone.now()
                    did_doc.published_by = request.user
                    did_doc.save(update_fields=["published_at", "published_by"])
        return ok(request,
                  did_state={"state": "finished", "did": did_obj.did, "environment": "PROD", "location": url},
                  did_doc_meta={"versionId": str(did_doc.version), "environment": "PROD", "published": True},
                  did_reg_meta={"method": "web"},
                  status=200)

    @route.get("/methods", auth=None)
    def list_did_methods(self, request):
        from src.dids.utils import did_methods
        items = [m["method"] for m in did_methods.methods]
        return JsonResponse({"items": items}, status=200, content_type="application/json")

    #def list_did_methods(self, request):
    #   from src.dids.utils import did_methods

   #     base_resolver = request.build_absolute_uri("/api/universal-resolver/identifiers/{did}")
   #     items = [
   #         {**m, "resolverEndpointTemplate": base_resolver}
   #         for m in did_methods.methods
   #     ]
   #     return JsonResponse({"items": items}, status=200, content_type="application/json")
