from django.db.models import QuerySet
from src.users.models import User, UserStatus

from typing import Optional
from django.db.models import Q
from src.organizations.models import Organization


def user_list(
    *,
    organization: Optional[Organization] = None,
    status: Optional[str] = None,
    role: Optional[str] = None,
    search: Optional[str] = None,
) -> QuerySet[User]:
    """
    Liste les utilisateurs avec filtres optionnels

    Args:
        organization: Filtrer par organisation
        status: Filtrer par statut
        role: Filtrer par rôle
        search: Recherche dans email, first_name, last_name
    """
    qs = User.objects.select_related("organization").all()

    if organization:
        qs = qs.filter(organization=organization)

    if status:
        qs = qs.filter(status=status)

    if role:
        qs = qs.filter(role=role)

    if search:
        search_term = search.strip()
        qs = qs.filter(
            Q(email__icontains=search_term)
            | Q(first_name__icontains=search_term)
            | Q(last_name__icontains=search_term)
        )

    return qs.order_by("-created_at")


def user_get_by_email(*, email: str) -> User:
    """Récupérer un utilisateur par email"""
    return User.objects.get(email=email)


def user_get_by_invitation_token(*, token: str) -> User:
    """Récupérer un utilisateur par token d'invitation"""
    return User.objects.get(invitation_token=token, status=UserStatus.INVITED)
