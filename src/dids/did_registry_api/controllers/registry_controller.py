from django.db import IntegrityError, transaction
from django.db.models import Exists, Max, OuterRef, Subquery
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.utils import timezone

from jsonschema.exceptions import ValidationError
from ninja import Query, Body
from ninja.errors import HttpError
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth

from src.dids import services
from src.api.pagination import Paginator
from src.core.apis import BaseAPIController
from src.dids.did_registry_api.schemas.envelopes import ok, err
from src.dids.did_document_compiler.builders import build_did_and_document
from src.dids.did_registry_api.services.preview import preview_single
from src.dids.models import (
    PublishRequest,
    Certificate,
    DID,
    UploadedPublicKey,
    DIDDocument,
)
from src.dids.did_registry_api.selectors.dids import (
    get_did_or_404,
    dids_for_org, dids_for_org_with_state,
)
from src.dids.did_registry_api.policies.access import (
    can_publish_prod,
    is_org_admin,
    can_manage_did,
)
from src.dids.proof_crypto_engine.jws2020.verify import verify_detached_jws
from src.dids.did_registry_api.selectors.did_documents import (
    candidate_for_publish,
    latest_draft,
    active_prod,
)
from src.dids.proof_crypto_engine.canonical.jcs import dumps_bytes, sha256_hex
from src.dids.did_registry_api.notifications.email import (
    send_publish_request_notification,
)
from src.dids.utils.ids import generate_key_id
from src.dids.utils.validators import validate_did_document
from src.organizations.models import Organization
from src.dids.services import bind_doc_to_keys
from src.dids import selectors


def _ensure_single_vm(doc: dict) -> dict:
    vms = doc.get("verificationMethod") or []
    if not isinstance(vms, list) or len(vms) != 1:
        raise HttpError(
            400, "Exactly one verificationMethod is required by platform policy."
        )
    return vms[0]


def _kid_jwk_purposes(doc: dict) -> tuple[str, dict, list[str]]:
    vm = _ensure_single_vm(doc)
    kid = vm.get("id")
    jwk = vm.get("publicKeyJwk") or {}
    purposes: list[str] = []
    for rel in (
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ):
        for ref in doc.get(rel, []):
            if ref == kid:
                purposes.append(rel)
    return kid, jwk, purposes


# Helper interne pour vérifier une proof JWS-2020 existante (detached, b64=false)
def _verify_existing_proof(doc: dict, jwk: dict) -> bool:
    proof = (doc or {}).get("proof") or {}
    jws = proof.get("jws")
    if not jws or ".." not in jws:
        return False
    protected_b64, signature_b64 = jws.split("..", 1)
    to_sign = dict(doc)
    to_sign.pop("proof", None)
    payload_str = dumps_bytes(to_sign).decode("utf-8")
    return verify_detached_jws(protected_b64, signature_b64, payload_str, jwk)


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class RegistryController(BaseAPIController):
    @route.post("/dids")
    @transaction.atomic
    def create_did(self, request, body: dict = Body(...)):
        """
        Body: {
          organization_id, document_type,
          certificate_id, key_id, purposes?: []
        }
        Policy: exactly one verificationMethod (single key).
        """
        org_id = body.get("organization_id")
        doc_type = body.get("document_type")
        cert_id = body.get("certificate_id")
        purposes = body.get("purposes")

        if not all([org_id, doc_type, cert_id]):
            return err(
                request,
                400,
                "organization_id, document_type, certificate_id are required",
                path="/api/registry/dids",
            )

        org = get_object_or_404(Organization, pk=org_id)
        owner = request.user
        cert = get_object_or_404(Certificate, pk=cert_id, organization=org)

        key_id = generate_key_id()

        try:
            did_str, document = build_did_and_document(
                organization=org,
                owner=owner,
                document_type=doc_type,
                jwk=cert.extracted_jwk,
                key_id=key_id,
                purposes=purposes if purposes not in (None, []) else None,
                services=None,
            )
        except ValueError as e:
            return err(request, 400, str(e), path="/api/registry/dids")

        vms = document.get("verificationMethod") or []
        if not isinstance(vms, list) or len(vms) != 1:
            return err(
                request,
                400,
                "Exactly one verificationMethod is required by platform policy.",
                path="/api/registry/dids",
            )

        validate_did_document(document)

        try:
            did_obj = DID.objects.create(
                did=did_str, organization=org, owner=owner, document_type=doc_type
            )
        except IntegrityError:
            return err(request, 409, "DID already exists", path="/api/registry/dids")

        # Persist key snapshot
        upk = UploadedPublicKey.objects.create(
            did=did_obj,
            key_id=key_id,
            key_type=UploadedPublicKey.KeyType.JSON_WEB_KEY_2020,
            version=1,
            certificate=cert,
            public_key_jwk=cert.extracted_jwk,
            public_key_jwk_snapshot=cert.extracted_jwk,
            purposes=purposes or [],
            is_active=True,
        )

        # Create first DID Document (v1, DRAFT)
        did_doc = DIDDocument.objects.create(
            did=did_obj,
            version=1,
            document=document,
            environment="DRAFT",
            is_active=False,
        )

        canon = dumps_bytes(document)
        digest = sha256_hex(canon)
        if hasattr(did_doc, "canonical_sha256"):
            did_doc.canonical_sha256 = digest
            did_doc.save(update_fields=["canonical_sha256"])

        # Audit trail binding
        bind_doc_to_keys(did_doc, {key_id: upk})

        return ok(
            request,
            did_state={
                "state": "wait",
                "did": did_obj.did,
                "didDocument": document,
                "environment": "DRAFT",
            },
            did_doc_meta={
                "versionId": "1",
                "environment": "DRAFT",
                "published": False,
                "canonical_sha256": digest,
            },
            did_reg_meta={"method": "web"},
            status=201,
        )

    @route.get("/dids")
    def list_dids_org(self, request):
        """
        Lists all DIDs for the caller's organization (ORG scope).
        Pagination via ?page=1&page_size=20.
        """
        user = request.user
        org_id = getattr(user, "organization_id", None) or getattr(
            getattr(user, "organization", None), "id", None
        )

        if not org_id:
            raise HttpError(400, "User has no organization context")

        # Subqueries to fetch latest active key material per DID
        latest_pk_qs = UploadedPublicKey.objects.filter(
            did_id=OuterRef("id"), is_active=True
        ).order_by("-version")

        # Exists: is there an active PROD document?
        prod_active_exists = DIDDocument.objects.filter(
            did_id=OuterRef("id"),
            environment="PROD",
            is_active=True,
        )

        qs = dids_for_org_with_state(org_id).annotate(
            is_published=Exists(prod_active_exists),
            latest_version=Max("documents__version"),
            latest_public_key_version=Subquery(latest_pk_qs.values("version")[:1]),
            latest_public_key_jwk=Subquery(latest_pk_qs.values("public_key_jwk")[:1]),
            latest_key_id=Subquery(latest_pk_qs.values("key_id")[:1]),
        )

        paginator = Paginator(default_page_size=20, max_page_size=100)
        rows, meta = paginator.paginate_queryset(qs, request)

        items = []
        for d in rows:
            items.append(
                {
                    "did": d.did,
                    "organization_id": str(getattr(d.organization, "id", org_id)),
                    "owner_id": str(d.owner_id),
                    "document_type": d.document_type,
                    "latest_version": d.latest_version or 0,
                    "key_id": d.latest_key_id,
                    "public_key_version": d.latest_public_key_version,
                    "public_key_jwk": d.latest_public_key_jwk,
                    "status": d.status,
                    "state": getattr(d, "state", "action"),
                }
            )

        return JsonResponse(
            {"items": items, "pagination": meta},
            status=200,
            content_type="application/json",
        )

    @route.get("/dids/preview")
    def preview_get(
        self,
        request,
        organization_id: str,
        document_type: str,
        certificate_id: str,
        purposes: list[str] | None = Query(None),
    ):
        try:
            data = preview_single(
                request.user, organization_id, document_type, certificate_id, purposes
            )
            return ok(
                request,
                did_state={
                    "state": "action",
                    "did": data["did"],
                    "didDocument": data["document"],
                },
                did_doc_meta={"canonical_sha256": data["canonical_sha256"]},
                did_reg_meta={"method": "web"},
                status=200,
            )

        except ValidationError as ve:
            return err(request, 400, str(ve), path="/api/registry/dids/preview")
        except ValueError as ve:
            return err(request, 400, str(ve), path="/api/registry/dids/preview")

    @route.post("/dids/preview")
    def preview_post(self, request, body: dict = Body(...)):
        """
        Body: { organization_id, document_type, certificate_id, key_id, purposes?: [] }
        """
        organization_id = body.get("organization_id")
        document_type = body.get("document_type")
        certificate_id = body.get("certificate_id")
        purposes = body.get("purposes")
        if not all([organization_id, document_type, certificate_id]):
            return err(
                request,
                400,
                "organization_id, document_type, certificate_id are required",
                path="/api/registry/dids/preview",
            )

        try:
            data = preview_single(
                request.user, organization_id, document_type, certificate_id, purposes
            )
            return ok(
                request,
                did_state={
                    "state": "action",
                    "did": data["did"],
                    "didDocument": data["document"],
                },
                did_doc_meta={"canonical_sha256": data["canonical_sha256"]},
                did_reg_meta={"method": "web"},
                status=200,
            )
        except ValidationError as ve:
            return err(request, 400, str(ve), path="/api/registry/dids/preview")
        except ValueError as ve:
            return err(request, 400, str(ve), path="/api/registry/dids/preview")

    @route.post("/dids/{did}/publish")
    def publish(self, request, did: str, body: dict = Body(...)):
        """
        If caller lacks PROD rights, creates a PublishRequest and returns wait/202.
        body: { "version"?: int }
        """
        # OTP is required in the JSON body: { "otp_code": "123456", "version"?: int }.

        did_obj = get_did_or_404(did)

        if not can_manage_did(request.user, did_obj):
            raise HttpError(403, "Only the DID owner can initiate publish flow.")

        version_raw = (body or {}).get("version", None)
        try:
            version = int(version_raw) if version_raw is not None else None
        except (TypeError, ValueError):
            return err(
                request,
                400,
                "version must be an integer",
                path=f"/api/registry/dids/{did}/publish",
            )

        # If a version was specified, ensure it's a DRAFT of this DID
        if version is not None:
            exists = DIDDocument.objects.filter(
                did=did_obj, version=version, environment="DRAFT"
            ).exists()
            if not exists:
                return err(
                    request,
                    404,
                    "Requested version not found or not DRAFT",
                    path=f"/api/registry/dids/{did}/publish",
                )

        if did_obj.status == DID.DIDStatus.DEACTIVATED:
            # Irreversible: do not allow further publishes
            return err(
                request,
                409,
                "DID_DEACTIVATED",
                path=f"/api/registry/dids/{did}/publish",
            )

        doc = candidate_for_publish(did_obj, version)
        if not doc:
            raise HttpError(404, "No DRAFT document to publish")

        # Enforce DRAFT only
        if getattr(doc, "environment", None) != "DRAFT":
            return err(
                request,
                400,
                "Only DRAFT documents can be published",
                path=f"/api/registry/dids/{did}/publish",
            )

        # Approval gate
        # if not (is_org_admin(request.user, did_obj.organization) or can_publish_prod(request.user, did_obj.organization)):
        if not can_publish_prod(request.user, did_obj.organization):
            pr, created = PublishRequest.objects.get_or_create(
                did=did_obj,
                environment="PROD",
                status=PublishRequest.Status.PENDING,
                defaults={"did_document": doc, "requested_by": request.user},
            )
            if created:
                # notify admins only on first creation; defer until commit
                transaction.on_commit(lambda: send_publish_request_notification(pr))
            else:
                # Optional: if there’s a newer DRAFT, keep the pending request pointing to it
                if pr.did_document_id != doc.id:
                    pr.did_document = doc
                    pr.save(update_fields=["did_document"])

            return ok(
                request,
                did_state={
                    "state": "wait",
                    "did": did_obj.did,
                    "environment": "PROD",
                    "reason": "approval_required",
                    "publishRequestId": pr.id,
                },
                did_doc_meta={
                    "versionId": str(doc.version),
                    "environment": "PROD",
                    "published": False,
                },
                did_reg_meta={"method": "web"},
                status=202,
            )

        # Signing disabled: publish as-is to PROD
        if not getattr(settings, "DIDS_SIGNING_ENABLED", False):
            url = services.publish_to_prod(doc)
            # audit trail on the document
            if hasattr(doc, "published_at") and hasattr(doc, "published_by"):
                doc.published_at = timezone.now()
                doc.published_by = request.user
                doc.save(update_fields=["published_at", "published_by"])
            return ok(
                request,
                did_state={
                    "state": "finished",
                    "did": did_obj.did,
                    "environment": "PROD",
                    "location": url,
                },
                did_doc_meta={
                    "versionId": str(doc.version),
                    "environment": "PROD",
                    "published": True,
                },
                did_reg_meta={"method": "web"},
                status=200,
            )

        # If signing re-enabled later, BYOS flow can be added back here.
        return err(
            request, 409, "SIGNING_DISABLED", path=f"/api/registry/dids/{did}/publish"
        )

    # @route.post("/dids/{did}/publish/signature")
    # def submit_signature(self, request, did: str, body: dict = Body(...)):
    #     if not getattr(settings, "DIDS_SIGNING_ENABLED", False):
    #         return err(
    #             request,
    #             409,
    #             "SIGNING_DISABLED",
    #             path=f"/api/registry/dids/{did}/publish/signature",
    #         )
    #     return err(
    #         request,
    #         409,
    #         "SIGNING_DISABLED",
    #         path=f"/api/registry/dids/{did}/publish/signature",
    #     )

    @route.get("/dids/{did}/document")
    def get_current_document(
        self,
        request,
        did: str,
        target: str = Query("draft", pattern="^(draft|prod)$"),
        version: int | None = None,
    ):
        did_obj = get_did_or_404(did)

        # Resolve document
        if version is not None:
            doc = did_obj.documents.filter(version=version).first()
        else:
            doc = latest_draft(did_obj) if target == "draft" else active_prod(did_obj)

        if not doc:
            raise HttpError(404, "No document found for the requested target")

        # Access control
        if doc.environment == "DRAFT":
            if not can_manage_did(request.user, did_obj):
                raise HttpError(403, "Forbidden: only the DID owner can read DRAFT")
        else:
            if not (
                can_manage_did(request.user, did_obj)
                or is_org_admin(request.user, did_obj.organization)
            ):
                raise HttpError(403, "Forbidden")

        # Canonical hash
        canon = dumps_bytes(doc.document)
        digest = sha256_hex(canon)

        # Bindings with certificate info
        bindings = []
        for kb in doc.key_bindings.select_related(
            "uploaded_public_key", "uploaded_public_key__certificate"
        ).all():
            upk = kb.uploaded_public_key
            cert = getattr(upk, "certificate", None)
            cert_id = str(getattr(cert, "id", "")) if cert else None
            cert_file = getattr(cert, "file", None) if cert else None
            cert_filename = (
                cert_file.name.split("/")[-1]
                if getattr(cert_file, "name", None)
                else None
            )
            cert_url = (
                request.build_absolute_uri(cert_file.url)
                if getattr(cert_file, "url", None)
                else None
            )

            bindings.append(
                {
                    "key_id": upk.key_id,
                    "public_key_version": upk.version,
                    "public_key_jwk": upk.public_key_jwk,
                    "purposes": upk.purposes,
                    "certificate": {
                        "id": cert_id,
                        "filename": cert_filename,
                        "url": cert_url,
                    },
                }
            )

        # Current key = first binding (single-VM policy)
        current_key = bindings[0] if bindings else None

        return ok(
            request,
            did_state={
                "state": "action",
                "did": did_obj.did,
                "environment": doc.environment,
                "version": doc.version,
                "didDocument": doc.document,
            },
            did_doc_meta={
                "versionId": str(doc.version),
                "environment": doc.environment,
                "published": bool(doc.is_active),
                "canonical_sha256": digest,
                "key": current_key,  # includes certificate {id, filename, url}
                "bindings": bindings,  # each binding includes its certificate details
            },
            did_reg_meta={"method": "web"},
            status=200,
        )

    @route.get("/dids/random-urls", auth=None)
    def random_urls(self, request, limit: int = 10):
        """
        Return up to `limit` random public DID URLs (active PROD).
        """
        try:
            lim = int(limit)
        except Exception:
            lim = 10
        lim = max(1, min(lim, 100))
    
        items = selectors.random_prod_dids(limit=lim)
        return JsonResponse({"items": items, "count": len(items)}, status=200)
        