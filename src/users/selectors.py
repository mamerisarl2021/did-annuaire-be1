from django.db.models import QuerySet
from datetime import timedelta
from django.utils import timezone
from src.core.exceptions import DomainValidationError
from src.users.models import User, UserStatus, UserRole

from django.db.models import Q
from src.organizations.models import Organization


def user_list(
    *,
    user = User,
    organization: Organization | None = None,
    status: str | None = None,
    search: str | None = None,
) -> QuerySet[User]:
    """
    Liste les utilisateurs avec filtres optionnels

    Args:
        organization: Filtrer par organisation
        status: Filtrer par statut
        role: Filtrer par rôle
        search: Recherche dans email, first_name, last_name
    """
    qs = User.objects.select_related("organization", "invited_by") \
            .only(
                "id", "email", "first_name", "last_name", "can_publish_prod", "functions",
                "role", "status", "created_at",
                "organization__name",
                "invited_by__email",
            )

    # Scope ORG_ADMIN
    if not user.is_superuser:
        if UserRole.ORG_ADMIN.value in user.role and user.organization:
            qs = qs.filter(organization=user.organization)
        else:
            # Non-admin users see nothing
            qs = qs.none()

    if status:
        qs = qs.filter(status=status)

    if search:
            s = search.strip()
            qs = qs.filter(Q(email__icontains=s) | Q(first_name__icontains=s) | Q(last_name__icontains=s))
    
    return qs.order_by("-created_at")

def user_get_invited_by_token(*, token: str) -> User:
    try:
        user = User.objects.get(invitation_token=token, status=UserStatus.INVITED)
    except User.DoesNotExist:
        raise DomainValidationError(message="Lien invalide", code="INVITE_INVALID")
    if user.invitation_sent_at and user.invitation_sent_at < timezone.now() - timedelta(
        days=7
    ):
        raise DomainValidationError(
            message="Le lien d'activation a expiré", code="INVITE_EXPIRED"
        )
    return user