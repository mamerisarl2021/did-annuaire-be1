import uuid

from django.db import transaction
from django.shortcuts import get_object_or_404
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from src.organizations.models import Organization
from src.users.models import User
from .models import DID, DIDDocument, Certificate, UploadedPublicKey
from src.dids.utils.builders import build_did_and_document, build_did_document_with_keys
from .schemas import CreateDIDResponse, CreateDIDRequest, PreviewDIDResponse
from .services import (
    draft_fill_hash,
    build_host,
    derive_org_slug,
    derive_user_slug,
    build_relpath,
    jcs_canonical_bytes,
    sha256_hex,
)
from src.dids.utils.validators import validate_did_document
from .utils.registrar_envelope import registrar_ok


@transaction.atomic
def _persist_keys(did: DID, key_specs: list[dict]):
    upk_ids = []
    for spec in key_specs:
        cert = spec["certificate"]
        upk = UploadedPublicKey.objects.create(
            did=did,
            key_id=spec["key_id"],
            key_type=UploadedPublicKey.KeyType.JSON_WEB_KEY_2020,
            certificate=cert,
            public_key_jwk=cert.extracted_jwk,
            public_key_jwk_snapshot=cert.extracted_jwk,
            purposes=spec.get("purposes") or [],
            is_active=True,
        )
        upk_ids.append(upk.id)
    return upk_ids


@api_controller("/registry", tags=["DID Registry"])
class DIDCreationController:
    @route.post("/dids", response=CreateDIDResponse)
    @transaction.atomic
    def create_did(self, request, payload: CreateDIDRequest):
        org = get_object_or_404(Organization, pk=payload.organization_id)
        owner = (
            get_object_or_404(User, pk=payload.owner_id)
            if payload.owner_id
            else request.user
        )

        # Build key inputs
        key_specs = []
        if payload.keys:
            # multi-key mode
            seen_ids = set()
            for k in payload.keys:
                if k.key_id in seen_ids:
                    raise HttpError(400, f"Duplicate key_id: {k.key_id}")
                seen_ids.add(k.key_id)
                cert = get_object_or_404(
                    Certificate, pk=k.certificate_id, organization=org
                )
                key_specs.append(
                    {"certificate": cert, "key_id": k.key_id, "purposes": k.purposes}
                )
        else:
            # legacy single-key
            if not (payload.certificate_id and payload.key_id):
                raise HttpError(
                    400, "Provide either keys[] or (certificate_id & key_id)"
                )
            cert = get_object_or_404(
                Certificate, pk=payload.certificate_id, organization=org
            )
            key_specs.append(
                {
                    "certificate": cert,
                    "key_id": payload.key_id,
                    "purposes": payload.purposes,
                }
            )

        # Build DID + DID Document (with strict purpose validation in builder)
        try:
            if payload.keys:
                did_str, document = build_did_document_with_keys(
                    organization=org,
                    owner=owner,
                    document_type=payload.document_type,
                    keys=[
                        {
                            "jwk": ks["certificate"].extracted_jwk,
                            "key_id": ks["key_id"],
                            "purposes": ks["purposes"],
                        }
                        for ks in key_specs
                    ],
                    services=payload.services,
                )
            else:
                did_str, document = build_did_and_document(
                    organization=org,
                    owner=owner,
                    document_type=payload.document_type,
                    jwk=key_specs[0]["certificate"].extracted_jwk,
                    key_id=key_specs[0]["key_id"],
                    purposes=key_specs[0]["purposes"],
                    services=payload.services,
                )
        except ValueError as e:
            raise HttpError(400, str(e))

        if DID.objects.filter(did=did_str).exists():
            raise HttpError(409, "DID already exists")

        did = DID.objects.create(
            did=did_str,
            organization=org,
            owner=owner,
            document_type=payload.document_type,
        )

        upk_ids = _persist_keys(did, key_specs)

        did_doc = DIDDocument.objects.create(
            did=did, version=1, document=document, environment="DRAFT", is_active=False
        )
        draft_fill_hash(did_doc)

        # p =  CreateDIDResponse(
        #    did=did.did,
        #    did_document_version=did_doc.version,
        #    environment=did_doc.environment,
        #    uploaded_public_key_id=upk_ids[0] if len(upk_ids)==1 else upk_ids[0]  # keep response stable; IDs available in a follow-up endpoint if needed
        # )

        return registrar_ok(
            request,
            did_state={
                "state": "wait",
                "did": did.did,
                "didDocument": did_doc.document,
                "environment": "DRAFT",
            },
            did_reg_meta={"method": "web"},
            did_doc_meta={
                "versionId": str(did_doc.version),
                "environment": "DRAFT",
                "published": False,
            },
            status=201,
        )

    @route.get("/dids/preview", response=PreviewDIDResponse)
    def preview_did(
        self,
        request,
        organization_id: uuid.UUID,
        document_type: str,
        certificate_id: uuid.UUID,
        key_id: str | None = None,
        purposes: list[str] | None = None,
    ):
        # Entrées
        org = get_object_or_404(Organization, pk=organization_id)
        owner = request.user

        try:
            if certificate_id and key_id:
                cert = get_object_or_404(
                    Certificate, pk=certificate_id, organization=org
                )
                did_str, document = build_did_and_document(
                    org,
                    owner,
                    document_type,
                    jwk=cert.extracted_jwk,
                    key_id=key_id,
                    purposes=purposes,
                )
            else:
                # look for keys[] in query params via request.GET — or prefer POST preview if you want body schema
                raise HttpError(
                    400,
                    "Provide (certificate_id & key_id) or call the POST preview variant supporting keys[]",
                )
        except ValueError as e:
            raise HttpError(400, str(e))

        # Valide le document contre le schéma officiel
        try:
            validate_did_document(document)
        except Exception as e:
            raise HttpError(400, f"Schema validation failed: {e}")

        # Hash canonique JCS (RFC 8785) pour comparaison côté FE
        canon = jcs_canonical_bytes(document)
        digest = sha256_hex(canon)

        # Calcule les URLs de publication (sans écrire sur le FS)
        host = build_host()
        org_slug = derive_org_slug(org)
        user_slug = derive_user_slug(owner)
        preprod_rel = build_relpath("PREPROD", org_slug, user_slug, document_type)
        prod_rel = build_relpath("PROD", org_slug, user_slug, document_type)

        p = PreviewDIDResponse(
            did=did_str,
            document=document,
            canonical_sha256=digest,
            did_url_preprod=f"https://{host}/{preprod_rel}",
            did_url_prod=f"https://{host}/{prod_rel}",
            organization_slug=org_slug,
            user_slug=user_slug,
            document_type=document_type,
            key_id=key_id,
        )

        return registrar_ok(
            request,
            did_state={"state": "action", "did": did_str, "didDocument": document},
            did_reg_meta={"method": "web"},
            did_doc_meta={
                "canonical_sha256": p.canonical_sha256,
                "document_type": p.document_type,
                "key_id": p.key_id,
            },
        )


# GET /api/registry/dids/preview?organization_id=12&document_type=permis_conduite_qrcode&certificate_id=34
