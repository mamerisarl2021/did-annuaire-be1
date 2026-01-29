from django.db.models import QuerySet
from datetime import timedelta
from django.utils import timezone
from src.core.exceptions import DomainValidationError
from src.users.models import User, UserStatus, UserRole

from django.db.models import Q, Count
from src.core.exceptions import APIError

def user_list(
    *,
    user: User,
    status: str | None = None,
    search: str | None = None,
) -> QuerySet[User]:
    """
    List users visible to the caller:
      - ORG_ADMIN -> only users in their org
      - SUPERUSER -> all users
    """
    qs = User.objects.select_related("organization", "invited_by").only(
        "id", "email", "first_name", "last_name", "can_publish_prod",
        "role", "status", "created_at",
        "organization__name",
        "invited_by__email",
    )

    if not (
            user.is_platform_admin
            or UserRole.ORG_ADMIN.value in user.role
        ):
            raise APIError(message="Permission denied", code="FORBIDDEN", status=403)
    
    qs = User.objects.select_related("organization", "invited_by")
    
    if not user.is_platform_admin:
        qs = qs.filter(organization=user.organization)
        
    if status:
        qs = qs.filter(status=status)

    if search:
        s = search.strip()
        qs = qs.filter(
            Q(email__icontains=s) |
            Q(first_name__icontains=s) |
            Q(last_name__icontains=s)
        )

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
    
def users_stats_for_actor(*, user) -> dict:
    """
    User statistics visible to the caller:
    - Platform admin: all users
    - ORG_ADMIN: users in their organization
    """

    if not (
        user.is_platform_admin
        or UserRole.ORG_ADMIN.value in user.role
    ):
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)

    qs = User.objects.all()

    if not user.is_platform_admin:
        qs = qs.filter(organization=user.organization)

    total = qs.count()

    # --- by status ---
    by_status_qs = (
        qs.values("status")
        .annotate(count=Count("id"))
    )
    by_status = {
        row["status"].lower(): row["count"]
        for row in by_status_qs
    }

    # --- by role (JSONField) ---
    by_role = {
        UserRole.ORG_ADMIN.value.lower(): qs.filter(role__contains=[UserRole.ORG_ADMIN.value]).count(),
        UserRole.ORG_MEMBER.value.lower(): qs.filter(role__contains=[UserRole.ORG_MEMBER.value]).count(),
        UserRole.AUDITOR.value.lower(): qs.filter(role__contains=[UserRole.AUDITOR.value]).count(),
    }

    return {
        "all": total,
        "by_status": by_status,
        "by_role": by_role,
    }