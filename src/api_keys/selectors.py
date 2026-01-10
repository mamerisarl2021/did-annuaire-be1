from django.db.models import QuerySet
from src.api_keys.models import APIKey


def api_key_list_by_organization(*, organization) -> QuerySet[APIKey]:
    """Liste des API Keys d'une organisation"""

    return (
        APIKey.objects.filter(organization=organization)
        .select_related("created_by")
        .order_by("-created_at")
    )
