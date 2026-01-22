# Universal Registrar + Resolver —
from django.db.models import Max
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from ninja.errors import HttpError
from ninja_extra import api_controller, route
from .models import DID, DIDDocument
from .schemas import CreateRequest, UpdateRequest, RegistrarState, DeactivateRequest
from .services import draft_fill_hash, deactivate_did


@api_controller("/universal-registrar", tags=["Universal Registrar"])
class UniversalRegistrarController:
    @route.post("/create")
    def create(self, request, method: str, payload: CreateRequest) -> RegistrarState:
        assert method == "web", "Only method=web is supported"
        doc = payload.didDocument
        if not doc:
            raise HttpError(
                400,
                "This registrar does not accept empty create payload. Use /registry/dids with certificate_id.",
            )

        did_str: str = doc.get("id")
        did = get_object_or_404(DID, did=did_str)
        version = (did.documents.aggregate(Max("version")).get("version__max") or 0) + 1
        did_doc = DIDDocument.objects.create(
            did=did, version=version, document=doc, environment="DRAFT", is_active=False
        )
        draft_fill_hash(did_doc)
        return RegistrarState(
            didState={"state": "finished", "did": did_str, "didDocument": doc},
            didDocumentMetadata={
                "created": (
                    did_doc.created_at.isoformat()
                    if hasattr(did_doc, "created_at") and did_doc.created_at
                    else None
                )
            },
            didRegistrationMetadata={"method": "web"},
        )

    @route.post("/update")
    def update(self, request, payload: UpdateRequest) -> RegistrarState:
        did = get_object_or_404(DID, did=payload.did)
        new_doc = payload.didDocument[-1] if payload.didDocument else {}
        version = (did.documents.aggregate(Max("version")).get("version__max") or 0) + 1
        did_doc = DIDDocument.objects.create(
            did=did,
            version=version,
            document=new_doc,
            environment="DRAFT",
            is_active=False,
        )
        draft_fill_hash(did_doc)
        # return RegistrarState(didState={"state": "finished", "did": did.did, "didDocument": new_doc})
        return registrar_ok(
            request,
            did_state={
                "state": "update",
                "did": did.did,
                "didDocument": new_doc,
                "environment": "DRAFT",
                "version": did_doc.version,
            },
            did_reg_meta={"method": "web"},
            did_doc_meta={
                "versionId": str(did_doc.version),
                "environment": "DRAFT",
                "published": False,
            },
            status=200,
        )

    @route.post("/deactivate")
    def deactivate(self, request, payload: DeactivateRequest) -> RegistrarState:
        did = get_object_or_404(DID, did=payload.did)
        did.status = DID.DIDStatus.DEACTIVATED
        did.save(update_fields=["status"])
        version = (did.documents.aggregate(Max("version")).get("version__max") or 0) + 1
        deactivated_doc = deactivate_did(did)
        DIDDocument.objects.create(
            did=did,
            version=version,
            document=deactivated_doc,
            environment="PROD",
            is_active=True,
        )
        return RegistrarState(didState={"state": "finished", "did": did.did})


@api_controller("/universal-resolver", tags=["Universal Resolver"])
class UniversalResolverController:
    @route.get("/identifiers/{identifier}")
    def resolve(self, request, identifier: str):
        accept = request.headers.get("Accept", "application/did")
        did = get_object_or_404(DID, did=identifier)
        doc_model = (
            did.documents.filter(environment="PROD", is_active=True)
            .order_by("-version")
            .first()
        )
        status = 410 if did.status == DID.DIDStatus.DEACTIVATED else 200
        if accept == "application/did-resolution":
            body = {
                "didDocument": (doc_model.document if doc_model else None),
                "didResolutionMetadata": {"contentType": "application/did+json"},
                "didDocumentMetadata": {
                    "versionId": (str(doc_model.version) if doc_model else None)
                },
            }
            return JsonResponse(body, status=status)
        return JsonResponse(doc_model.document if doc_model else {}, status=status)
