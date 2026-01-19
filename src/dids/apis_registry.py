from datetime import datetime
from django.utils import timezone as dj_tz
from django.shortcuts import get_object_or_404
from ninja.params import Query
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from .models import DID, DIDDocument, PublishRequest
from src.dids.utils.notifications import send_publish_decision_notification
from .schemas import PublishRequestOut, ValidateResponse, PublishResponse
from .services import publish_preprod, publish_prod, jcs_canonical_bytes, sha256_hex
from src.dids.utils.validators import validate_did_document
from .policies import is_org_admin, can_publish_prod
from src.dids.utils.notifications import send_publish_request_notification
from .utils.registrar_envelope import registrar_ok


def _pr_out(pr: PublishRequest) -> PublishRequestOut:
    return PublishRequestOut(
        id=pr.id,
        did=pr.did.did,
        version=pr.did_document.version,
        environment=pr.environment,
        status=pr.status,
        requested_by=getattr(pr.requested_by, "email", None),
        decided_by=getattr(pr.decided_by, "email", None) if pr.decided_by else None,
        decided_at=pr.decided_at.isoformat() if pr.decided_at else None,
        note=pr.note or None,
    )


def _now_utc():
    return datetime.now(dj_tz.utc)


@api_controller("/registry", tags=["DID Registry"])
class RegistryController:
    # TODO: protéger via auth (decorator ou middleware)
    @route.post("/dids/{did}/publish")
    def publish(
        self,
        request,
        did: str,
        env: str = Query(..., pattern="^(preprod|prod)$"),
        version: int | None = None,
    ):
        did_obj = get_object_or_404(DID, did=did)
        user = request.user

        # Sélection de la version à publier
        if version is not None:
            doc = get_object_or_404(DIDDocument, did=did_obj, version=version)
        else:
            if env == "preprod":
                doc = (
                    did_obj.documents.filter(environment="DRAFT")
                    .order_by("-version")
                    .first()
                )
            else:
                doc = (
                    did_obj.documents.filter(environment="PREPROD")
                    .order_by("-version")
                    .first()
                    or did_obj.documents.filter(environment="DRAFT")
                    .order_by("-version")
                    .first()
                )
        if not doc:
            raise HttpError(404, "No document to publish for the requested environment")

        org = did_obj.organization

        # PREPROD → FINISHED (published)
        if env == "preprod":
            if not (is_org_admin(user, org) or getattr(user, "is_superuser", False)):
                raise HttpError(403, "Not allowed to publish to PREPROD")
            url = publish_preprod(doc)
            return registrar_ok(
                request,
                did_state={
                    "state": "finished",
                    "did": did_obj.did,
                    "didDocument": doc.document,
                    "environment": "PREPROD",
                    "location": url,
                },
                did_reg_meta={"method": "web"},
                did_doc_meta={
                    "versionId": str(doc.version),
                    "environment": "PREPROD",
                    "published": True,
                },
                status=200,
            )

        # env == "prod"
        if is_org_admin(user, org) or can_publish_prod(user, org):
            url = publish_prod(doc)
            return registrar_ok(
                request,
                did_state={
                    "state": "finished",
                    "did": did_obj.did,
                    "didDocument": doc.document,
                    "environment": "PROD",
                    "location": url,
                },
                did_reg_meta={"method": "web"},
                did_doc_meta={
                    "versionId": str(doc.version),
                    "environment": "PROD",
                    "published": True,
                },
                status=200,
            )

        # Pas autorisé → demande d’approbation
        pr = PublishRequest.objects.create(
            did=did_obj,
            did_document=doc,
            environment="PROD",
            requested_by=user,
            status=PublishRequest.Status.PENDING,
        )
        send_publish_request_notification(pr)
        return registrar_ok(
            request,
            did_state={
                "state": "wait",
                "did": did_obj.did,
                "environment": "PROD",
                "reason": "approval_required",
                "publishRequestId": pr.id,
            },
            did_reg_meta={"method": "web"},
            did_doc_meta={
                "versionId": str(doc.version),
                "environment": "PROD",
                "published": False,
            },
            status=202,
        )

    @route.post("/dids/{did}/validate", response=ValidateResponse)
    def validate(self, request, did: str, version: int | None = None):
        did_obj = get_object_or_404(DID, did=did)
        if version is not None:
            doc = get_object_or_404(DIDDocument, did=did_obj, version=version)
        else:
            doc = did_obj.documents.order_by("-version").first()
        if not doc:
            raise HttpError(404, "No DID Document found")

        # Validation schéma
        validate_did_document(doc.document)

        # Hash JCS
        canon = jcs_canonical_bytes(doc.document)
        digest = sha256_hex(canon)

        # Persister le hash si DRAFT (pratique pour l’audit)
        if doc.environment == "DRAFT" and doc.canonical_sha256 != digest:
            doc.canonical_sha256 = digest
            doc.save(update_fields=["canonical_sha256"])

        return ValidateResponse(
            did=did_obj.did, version=doc.version, valid=True, canonical_sha256=digest
        )

    @route.get("/publish-requests", response=list[PublishRequestOut])
    def list_publish_requests(
        self,
        request,
        org_id: int,
        status: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ):
        # AuthZ: seul ORG_ADMIN de l'org peut lister
        # On récupère l'org via un PR au moins; sinon 404
        qs = PublishRequest.objects.select_related(
            "did", "did__organization", "requested_by", "did_document"
        ).filter(did__organization_id=org_id)
        sample_org = None
        sample = qs.first()
        if sample:
            sample_org = sample.did.organization
        else:
            # si aucune PR, on charge l'org via dids si besoin (facultatif)
            from src.organizations.models import Organization

            sample_org = get_object_or_404(Organization, pk=org_id)
        if not is_org_admin(request.user, sample_org):
            raise HttpError(403, "Not allowed")

        if status:
            qs = qs.filter(status=status)
        qs = qs.order_by("-created_at")[offset : offset + min(200, limit)]

        return [_pr_out(pr) for pr in qs]

    @route.post("/publish-requests/{pr_id}/approve", response=PublishResponse)
    def approve_publish_request(self, request, pr_id: int, note: str | None = None):
        pr = get_object_or_404(
            PublishRequest.objects.select_related(
                "did", "did_document", "did__organization"
            ),
            pk=pr_id,
        )
        org = pr.did.organization
        if not is_org_admin(request.user, org):
            raise HttpError(403, "Not allowed")
        if pr.status != PublishRequest.Status.PENDING:
            raise HttpError(400, "Request is not pending")

        # Marquer approuvé
        pr.status = PublishRequest.Status.APPROVED
        pr.decided_by = request.user
        pr.decided_at = dj_tz.now()
        pr.note = note or pr.note
        pr.save(update_fields=["status", "decided_by", "decided_at", "note"])

        # Publier en PROD
        url = publish_prod(pr.did_document)

        # Notifier le demandeur
        send_publish_decision_notification(pr)

        return PublishResponse(
            did=pr.did.did,
            environment="PROD",
            version=pr.did_document.version,
            url=url,
            state="finished",
        )

    @route.post("/publish-requests/{pr_id}/reject", response=PublishResponse)
    def reject_publish_request(self, request, pr_id: int, note: str | None = None):
        pr = get_object_or_404(
            PublishRequest.objects.select_related(
                "did", "did_document", "did__organization"
            ),
            pk=pr_id,
        )
        org = pr.did.organization
        if not is_org_admin(request.user, org):
            raise HttpError(403, "Not allowed")
        if pr.status != PublishRequest.Status.PENDING:
            raise HttpError(400, "Request is not pending")

        pr.status = PublishRequest.Status.REJECTED
        pr.decided_by = request.user
        pr.decided_at = dj_tz.now()
        pr.note = note or pr.note
        pr.save(update_fields=["status", "decided_by", "decided_at", "note"])

        # Notifier le demandeur
        send_publish_decision_notification(pr)

        return PublishResponse(
            did=pr.did.did,
            environment="PROD",
            version=pr.did_document.version,
            url=None,
            state="rejected",
        )
