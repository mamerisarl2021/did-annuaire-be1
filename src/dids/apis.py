from ninja_extra import api_controller, route, ControllerBase
from ninja_jwt.authentication import JWTAuth
from ninja import File
from ninja import UploadedFile
from django.shortcuts import get_object_or_404

from src.dids.models import Application, DIDDocument
from src.dids import services, selectors
from src.users.models import UserRole


@api_controller("/applications", tags=["Applications"], auth=JWTAuth())
class ApplicationController(ControllerBase):
    @route.post("/")
    def create_application(self, name: str, description: str = ""):
        """Créer une application"""

        user = self.context.request.auth

        app = services.application_create(
            organization=user.organization,
            created_by=user,
            name=name,
            description=description,
        )

        return {
            "id": app.id,
            "name": app.name,
            "slug": app.slug,
            "description": app.description,
            "created_at": app.created_at.isoformat(),
        }

    @route.get("/")
    def list_applications(self):
        """Lister les applications de mon organisation"""

        user = self.context.request.auth
        apps = selectors.application_list_by_organization(
            organization=user.organization
        )

        return [
            {
                "id": app.id,
                "name": app.name,
                "slug": app.slug,
                "description": app.description,
                "created_at": app.created_at.isoformat(),
            }
            for app in apps
        ]


@api_controller("/dids", tags=["DID Documents"], auth=JWTAuth())
class DIDController(ControllerBase):
    @route.post("/create")
    def create_did_document(
        self,
        application_id: int,
        domain: str,
        certificate_file: UploadedFile = File(...),
    ):
        """
        Créer un DID Document

        La plateforme génère automatiquement le DID Document W3C
        à partir du certificat uploadé.
        """

        user = self.context.request.auth

        app = get_object_or_404(
            Application, id=application_id, organization=user.organization
        )

        did_doc = services.did_document_create(
            application=app,
            ncreated_by=user,
            domain=domain,
            certificate_file=certificate_file,
        )

        return {
            "id": did_doc.id,
            "did": did_doc.did,
            "status": did_doc.status,
            "version": did_doc.version,
            "domain": did_doc.domain,
            "created_at": did_doc.created_at.isoformat(),
        }

    @route.get("/")
    def list_did_documents(self, status: str = None):
        """Lister les DID Documents de mon organisation"""

        user = self.context.request.auth
        docs = selectors.did_document_list_by_organization(
            organization=user.organization, status=status
        )

        return [
            {
                "id": doc.id,
                "did": doc.did,
                "status": doc.status,
                "application": doc.application.name,
                "version": doc.version,
                "created_at": doc.created_at.isoformat(),
                "preprod_published_at": doc.preprod_published_at.isoformat()
                if doc.preprod_published_at
                else None,
                "prod_published_at": doc.prod_published_at.isoformat()
                if doc.prod_published_at
                else None,
            }
            for doc in docs
        ]

    @route.get("/{did_doc_id}")
    def get_did_document(self, did_doc_id: int):
        """Obtenir les détails d'un DID Document"""

        user = self.context.request.auth

        doc = _get_did_or_404_helper(did_doc_id, user)

        return {
            "id": doc.id,
            "did": doc.did,
            "status": doc.status,
            "version": doc.version,
            "domain": doc.domain,
            "document": doc.document,
            "application": {"id": doc.application.id, "name": doc.application.name},
            "created_at": doc.created_at.isoformat(),
            "validated_at": doc.validated_at.isoformat() if doc.validated_at else None,
            "prod_published_at": doc.prod_published_at.isoformat()
            if doc.prod_published_at
            else None,
        }

    @route.post("/{did_doc_id}/publish-draft")
    def publish_draft(self, did_doc_id: int):
        """Publier en pré-production (draft)"""

        user = self.context.request.auth

        doc = _get_did_or_404_helper(did_doc_id, user)

        services.did_document_publish_draft(did_document=doc, published_by=user)

        return self.create_response(
            message="Published to draft successfully",
            extra={"status": "PREPROD"},
            status_code=201,
        )

    @route.post("/{did_doc_id}/validate")
    def validate_did_document(self, did_doc_id: int):
        """Admin org valide le DID Document"""

        user = self.context.request.auth

        if user.role != UserRole.ORG_ADMIN:
            return self.create_response(
                message="Only ORG_ADMIN can validate", extra={}, status_code=403
            )

        doc = _get_did_or_404_helper(did_doc_id, user)

        services.did_document_validate(did_document=doc, validated_by=user)

        return self.create_response(
            message="DID Document validated successfully", extra={}, status_code=201
        )

    @route.post("/{did_doc_id}/publish-production")
    def publish_production(self, did_doc_id: int):
        """Publier en production"""

        user = self.context.request.auth

        doc = _get_did_or_404_helper(did_doc_id, user)

        try:
            services.did_document_publish_production(
                did_document=doc, published_by=user
            )
            return self.create_response(
                message="Published to production successfully",
                extra={"status": "PUBLISHED"},
                status_code=201,
            )
        except PermissionError as e:
            return self.create_response(message=str(e), extra={}, status_code=403)

    @route.post("/{did_doc_id}/revoke")
    def revoke_did_document(self, did_doc_id: int, reason: str):
        """Révoquer un DID Document"""

        user = self.context.request.auth

        if user.role != UserRole.ORG_ADMIN:
            return self.create_response(
                message="Only ORG_ADMIN can revoke", extra={}, status_code=403
            )

        doc = _get_did_or_404_helper(did_doc_id, user)

        services.did_document_revoke(did_document=doc, revoked_by=user, reason=reason)
        return self.create_response(
            message="DID Document revoked successfully", extra={}, status_code=200
        )


def _get_did_or_404_helper(did_doc_id: int, user) -> DIDDocument:
    return get_object_or_404(
        DIDDocument, id=did_doc_id, application__organization=user.organization
    )
