from django.db.models import QuerySet
from src.dids.models import Application, DIDDocument


def application_list_by_organization(*, organization) -> QuerySet[Application]:
    """Liste des applications d'une organisation"""
    return (
        Application.objects.filter(organization=organization, is_active=True)
        .select_related("organization", "created_by")
        .order_by("-created_at")
    )


def did_document_list_by_organization(
    *, organization, status=None
) -> QuerySet[DIDDocument]:
    """Liste des DID Documents d'une organisation"""
    qs = (
        DIDDocument.objects.filter(application__organization=organization)
        .select_related(
            "application", "created_by", "validated_by", "prod_published_by"
        )
        .prefetch_related("public_keys")
    )

    if status:
        qs = qs.filter(status=status)

    return qs.order_by("-created_at")


def did_document_get_by_did(*, did: str) -> DIDDocument:
    """Récupérer un DID Document par son DID"""
    return (
        DIDDocument.objects.select_related("application__organization")
        .prefetch_related("public_keys")
        .get(did=did)
    )
