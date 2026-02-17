import uuid

from datetime import timedelta

from django.db.models import QuerySet
from django.utils import timezone
from django.db.models.expressions import RawSQL
from django.db.models import Q, Count

from src.core.exceptions import APIError
from src.core.exceptions import DomainValidationError
from src.users.models import User, UserStatus, UserRole


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
        "id",
        "email",
        "first_name",
        "last_name",
        "can_publish_prod",
        "role",
        "status",
        "created_at",
        "organization__name",
        "invited_by__email",
    )

    if not (user.is_platform_admin or UserRole.ORG_ADMIN.value in user.role):
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)

    qs = User.objects.select_related("organization", "invited_by")

    if not user.is_platform_admin:
        qs = qs.filter(organization=user.organization)

    if status:
        qs = qs.filter(status=status)

    if search:
        s = search.strip()
        qs = qs.filter(
            Q(email__icontains=s)
            | Q(first_name__icontains=s)
            | Q(last_name__icontains=s)
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
    if not (user.is_platform_admin or UserRole.ORG_ADMIN.value in user.role):
        raise APIError(message="Permission denied", code="FORBIDDEN", status=403)

    base_qs = User.objects.all()

    if not user.is_platform_admin:
        base_qs = base_qs.filter(organization=user.organization)

    # --- total ---
    total = base_qs.count()

    # --- by status ---
    by_status = {
        row["status"].lower(): row["count"]
        for row in (base_qs.values("status").annotate(count=Count("id")))
    }

    # --- by role (single pass, JSON explode) ---
    role_qs = (
        base_qs.annotate(role_item=RawSQL("jsonb_array_elements_text(role)", []))
        .values("role_item")
        .annotate(count=Count("id"))
    )

    by_role = {row["role_item"].lower(): row["count"] for row in role_qs}

    return {
        "all": total,
        "by_status": by_status,
        "by_role": by_role,
    }


def user_get_by_id(*, user_id: uuid.UUID) -> User:
    """Get user by ID"""
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        raise APIError(message="User not found", code="USER_NOT_FOUND", status=404)


def user_get_for_update(*, user_id: uuid.UUID) -> User:
    """Get user with select_for_update lock"""
    try:
        return User.objects.select_for_update().get(id=user_id)
    except User.DoesNotExist:
        raise APIError(message="User not found", code="USER_NOT_FOUND", status=404)


def user_get_by_email(*, email: str) -> User | None:
    """Get user by email - returns None if not found"""
    try:
        return User.objects.get(email=email.strip().lower())
    except User.DoesNotExist:
        return None


def user_get_by_reset_token(*, token: str) -> User | None:
    """
    Get user by password reset token.
    Returns None if token not found, expired, or invalid.
    """
    try:
        return User.objects.get(
            password_reset_token=token,
            password_reset_token_expires_at__gt=timezone.now()
        )
    except User.DoesNotExist:
        return None


def user_get_info(*, user_id: uuid.UUID, requesting_user: User) -> dict:
    """
    Get user info - only org admins or the user themselves can access
    """
    target_user = user_get_by_id(user_id=user_id)

    # Permission check
    if not (requesting_user.is_org_admin or requesting_user.id == target_user.id):
        raise APIError(message="Permission Denied", code="FORBIDDEN", status=403)

    # Check same organization (unless platform admin)
    if not requesting_user.is_platform_admin:
        if target_user.organization_id != requesting_user.organization_id:
            raise APIError(message="Permission Denied", code="FORBIDDEN", status=403)

    return {
        "id": str(target_user.id),
        "email": target_user.email,
        "first_name": target_user.first_name,
        "last_name": target_user.last_name,
        "phone": target_user.phone,
        "role": target_user.role,
        "functions": target_user.functions,
        "can_publish_prod": target_user.can_publish_prod,
        "status": target_user.status,
        "organization_id": str(target_user.organization_id)
        if target_user.organization_id
        else None,
        "is_auditor": UserRole.AUDITOR.value in target_user.role,
    }
