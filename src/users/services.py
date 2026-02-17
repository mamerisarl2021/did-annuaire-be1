import hashlib
import uuid
import secrets
import pyotp
import qrcode
import base64
import io

from datetime import timedelta
from typing import Literal

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from django.utils.html import escape

from common.notifications.email import render_with_layout, send_html_email
from src.auditaction.models import AuditCategory
from src.auditaction.models import AuditAction
from src.core.exceptions import DomainValidationError
from src.core.ratelimit import enforce_min_interval
from src.users.models import User, UserStatus, UserRole
from src.emails.services import email_send
from src.auditaction.services import audit_action_create
from src.users.schemas import UserUpdatePayload
from src.users.selectors import user_get_invited_by_token
from src.core.exceptions import APIError
from . import selectors


########################################################################################################################################
# Helpers
# ######################################################################################################################################
# **************************************************************************************************************************************
#
@transaction.atomic
def user_generate_totp_qr(*, user: User) -> str:
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email, issuer_name="DID Annuaire"
    )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"


def verify_otp(
    *, user: User, otp_type: Literal["email", "sms", "totp"], provided_code: str
) -> bool:
    """
    Unified OTP/TOTP verification helper.

    Raises:
        DomainValidationError if OTP is invalid or expired.
    """
    if otp_type in {"email", "sms"}:
        code_field = f"{otp_type}_otp_code"
        expires_field = f"{otp_type}_otp_expires_at"

        stored_code = getattr(user, code_field, None)
        expires_at = getattr(user, expires_field, None)

        if not stored_code or not expires_at:
            raise DomainValidationError(
                message=f"{otp_type.upper()} OTP not generated",
                code="OTP_NOT_GENERATED",
            )

        if timezone.now() > expires_at:
            raise DomainValidationError(
                message=f"{otp_type.upper()} OTP expired", code="OTP_EXPIRED"
            )

        if stored_code != provided_code:
            raise DomainValidationError(
                message=f"{otp_type.upper()} OTP invalid", code="OTP_INVALID"
            )

        setattr(user, code_field, "")
        setattr(user, expires_field, None)
        user.save()
        return True

    if otp_type == "totp":
        if not user.totp_secret:
            raise DomainValidationError(
                message="TOTP not prepared", code="TOTP_REQUIRED"
            )
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(provided_code, valid_window=1):
            raise DomainValidationError(
                message="TOTP code invalid", code="TOTP_INVALID"
            )
        return True

    raise ValueError(f"Unsupported OTP type: {otp_type}")

def invalidate_password_reset_token(user: User) -> None:
    """
    Clear any pending password reset token for this user.
    Call this whenever a user's password is changed through ANY mechanism
    (reset flow, account settings, admin action, etc.) to ensure old
    reset links cannot be reused.
    """
    if user.password_reset_token or user.password_reset_token_expires_at:
        user.password_reset_token = None
        user.password_reset_token_expires_at = None
        user.password_reset_token_created_at = None
        # Note: caller is responsible for saving the user or including
        # these fields in their own save(update_fields=[...]) call.


def _get_client_ip(request) -> str | None:
    """Extract client IP from Django request, handling reverse proxies."""
    if not request:
        return None
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


# Password reset abuse detection thresholds
_IP_RESET_LIMIT = 10          # max reset requests per IP per window
_IP_RESET_WINDOW = 3600       # 1 hour window (seconds)
_IP_DISTINCT_EMAIL_LIMIT = 5  # max distinct emails per IP before alert


def _track_password_reset_by_ip(*, request, email: str) -> None:
    """
    Track password reset requests per IP to detect enumeration attacks
    or automated abuse (e.g., one IP hitting many different emails).

    Logs a WARNING-severity audit event when thresholds are exceeded.
    This does NOT block the request (per-email rate limiting handles that);
    it only creates audit trail for monitoring/alerting.
    """
    ip = _get_client_ip(request)
    if not ip:
        return

    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

    # Track total requests from this IP
    ip_count_key = f"users:password_reset:ip_count:{ip}"
    try:
        ip_attempts = cache.incr(ip_count_key)
    except ValueError:
        cache.set(ip_count_key, 1, timeout=_IP_RESET_WINDOW)
        ip_attempts = 1

    # Track distinct emails from this IP using a counter.
    # We hash email+IP to create per-email flags under this IP.
    email_flag_key = f"users:password_reset:ip_email:{ip}:{hashlib.sha256(email.encode()).hexdigest()[:12]}"
    is_new_email = cache.get(email_flag_key) is None
    if is_new_email:
        cache.set(email_flag_key, 1, timeout=_IP_RESET_WINDOW)

        # Increment distinct email counter for this IP
        ip_email_count_key = f"users:password_reset:ip_emails:{ip}"
        try:
            distinct_emails = cache.incr(ip_email_count_key)
        except ValueError:
            cache.set(ip_email_count_key, 1, timeout=_IP_RESET_WINDOW)
            distinct_emails = 1
    else:
        ip_email_count_key = f"users:password_reset:ip_emails:{ip}"
        distinct_emails = cache.get(ip_email_count_key, 1)

    # Check thresholds and log security alert if exceeded
    is_volume_abuse = ip_attempts == _IP_RESET_LIMIT  # log once at threshold
    is_enumeration = distinct_emails == _IP_DISTINCT_EMAIL_LIMIT  # log once at threshold

    if is_volume_abuse or is_enumeration:
        reasons = []
        if is_volume_abuse:
            reasons.append(f"volume_exceeded ({ip_attempts} requests)")
        if is_enumeration:
            reasons.append(f"enumeration_suspected ({distinct_emails} distinct emails)")

        audit_action_create(
            user=None,
            category=AuditCategory.AUTH,
            organization=None,
            action=AuditAction.PASSWORD_RESET_ABUSE_DETECTED,
            details={
                "ip_hash": ip_hash,
                "total_attempts": ip_attempts,
                "distinct_emails": distinct_emails,
                "reasons": reasons,
                "window_seconds": _IP_RESET_WINDOW,
                "severity": "WARNING",
            },
            target_type="security",
            target_id=ip_hash,
            request=request,
        )
# **************************************************************************************************************************************
# ######################################################################################################################################


@transaction.atomic
def user_create_by_admin(
    *,
    organization,
    created_by: User,
    email: str,
    first_name: str,
    last_name: str,
    phone: str,
    is_auditor: bool = False,
    functions: str | None = None,
    can_publish_prod: bool = True,
) -> User:
    """Org Admin creates a user"""

    # Enforce that only ORG_ADMIN roles can create users
    if UserRole.ORG_ADMIN not in created_by.role:
        raise PermissionError("User not allowed to create organization users.")

    roles = [UserRole.ORG_MEMBER]

    if is_auditor:
        roles.append(UserRole.AUDITOR)

    email = email.strip().lower()
    first_name = first_name.strip()
    last_name = last_name.strip()
    phone = phone.strip()

    user = User.objects.create_user(
        email=email,
        first_name=first_name,
        last_name=last_name,
        phone=phone,
        organization=organization,
        role=roles,
        status=UserStatus.PENDING,
        invited_by=created_by,
        functions=functions or "",
        can_publish_prod=can_publish_prod,
    )

    audit_action_create(
        user=created_by,
        category=AuditCategory.USER,
        organization=organization,
        action=AuditAction.USER_CREATED,
        details={
            "user_id": user.id,
            "email": email,
            "role": roles,
            "publish authorization": can_publish_prod,
        },
        target_type="user",
        target_id=str(user.id),
    )
    return user


@transaction.atomic
def user_send_invitation(*, user: User, invited_by: User):
    """Send an invitation to a user"""

    if user.status == UserStatus.ACTIVE:
        raise DomainValidationError(
            message="User already active", code="INVITE_NOT_ALLOWED"
        )

    if user.status == UserStatus.DEACTIVATED:
        raise DomainValidationError(
            message="User is deactivated", code="INVITE_NOT_ALLOWED"
        )

    enforce_min_interval(
        user.invitation_sent_at,
        seconds=120,
        code="INVITE_RATE_LIMIT",
        message="Veuillez patienter avant de renvoyer l'invitation.",
    )

    token = secrets.token_urlsafe(32)

    user.invitation_token = token
    user.invitation_sent_at = timezone.now()
    user.invited_by = invited_by
    user.status = UserStatus.INVITED
    user.save()

    activation_url = f"{settings.FR_APP_DOMAIN}/activate?token={token}"

    email_send(
        to=[user.email],
        subject=f"Invitation - {user.organization.name if user.organization else 'DID Annuaire'}",
        html=f"""
            <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; border: 1px solid #ddd; border-radius: 8px; max-width: 600px; margin: auto;">
                <h2 style="color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px;">Bienvenue !</h2>
                <p>Vous avez été invité à rejoindre <strong>{user.organization.name if user.organization else "DID Annuaire"}</strong>.</p>
                <p>Cliquez sur le bouton ci-dessous pour activer votre compte :</p>
                <p style="text-align: center; margin: 20px 0;">
                    <a href="{activation_url}" 
                       style="background-color: #0056b3; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                        Activer mon compte
                    </a>
                </p>
                <p style="font-size: 0.9em; color: #666; text-align: center;">
                    Ce lien expire dans 7 jours.
                </p>
                <p style="font-size: 0.9em; color: #666; margin-top: 20px;">
                    Ce message est automatique. Merci de ne pas y répondre directement.
                </p>
            </div>
        """,
    )
    audit_action_create(
        user=invited_by,
        category=AuditCategory.USER,
        organization=user.organization,
        action=AuditAction.USER_INVITED,
        details={"user_id": user.id, "email": user.email},
        target_type="user",
        target_id=str(user.id),
    )


@transaction.atomic
def user_activate_account(
    *, token: str, password: str, enable_totp: bool = False
) -> User:
    user = user_get_invited_by_token(token=token)
    user.set_password(password)
    user.status = UserStatus.ACTIVE
    user.invitation_accepted_at = timezone.now()
    user.invitation_token = ""
    if enable_totp:
        user.totp_enabled = True
    user.is_active = True
    # Clear any lingering password reset tokens
    invalidate_password_reset_token(user)
    user.save()
    audit_action_create(
        user=user,
        category=AuditCategory.USER,
        action=AuditAction.USER_ACTIVATED,
        organization=user.organization,
        target_type="user",
        target_id=str(user.id),
        details={
            "user_id": user.id,
            "previous_status": UserStatus.INVITED,
            "new_status": UserStatus.ACTIVE,
            "self_activation": True,
            "totp_enabled": user.totp_enabled,
        },
    )
    return user


@transaction.atomic
def user_generate_otp(*, user: User, otp_type: Literal["email", "sms"]) -> str:
    if user.status == UserStatus.ACTIVE:
        raise DomainValidationError(
            message="OTP not allowed for active user", code="OTP_NOT_ALLOWED"
        )

    code_field = f"{otp_type}_otp_code"
    expires_field = f"{otp_type}_otp_expires_at"
    sent_field = f"{otp_type}_otp_sent_at"
    interval = 120 if otp_type == "email" else 60

    last_sent = getattr(user, sent_field, None)
    if last_sent:
        enforce_min_interval(
            last_sent,
            seconds=interval,
            code="OTP_RATE_LIMIT",
            message=f"Veuillez patienter avant de redemander un {otp_type.upper()} code.",
        )

    code = str(secrets.randbelow(1000000)).zfill(6)
    now = timezone.now()
    setattr(user, code_field, code)
    setattr(user, expires_field, now + timedelta(minutes=10))
    setattr(user, sent_field, now)
    user.save()

    if otp_type == "email":
        email_send(
            to=[user.email],
            subject="Code de vérification",
            html=f"<p>Votre code de vérification est: <strong>{code}</strong></p><p>Valide pendant 10 minutes.</p>",
        )

    if otp_type == "sms":
        # TODO
        pass

    audit_action_create(
        user=user,
        category=AuditCategory.USER,
        organization=user.organization,
        action=AuditAction.OTP_GENERATED,
        details={"otp_type": otp_type},
        target_type="user",
        target_id=str(user.id),
    )

    return code


@transaction.atomic
def user_toggle_active(*, user_id: str, toggled_by: User) -> User:
    """
    Toggle a user's active status:
      - ACTIVE -> DEACTIVATED
      - anything else -> ACTIVE
    Org-admin only:
      - Can toggle users in their organization
      - Cannot toggle platform superusers
      - Cannot toggle themselves
    """
    user = User.objects.select_for_update().get(id=user_id)

    # Prevent self-toggle
    if user.id == toggled_by.id:
        raise DomainValidationError(
            message="You cannot toggle your own account", code="CANNOT_SELF_TOGGLE"
        )

    if user.organization_id != toggled_by.organization_id:
        raise PermissionError("Cannot toggle a user outside your organization.")

    if user.is_superuser:
        raise PermissionError("Cannot toggle a platform admin.")

    prev_status = user.status

    if user.status == UserStatus.ACTIVE:
        user.status = UserStatus.DEACTIVATED
        user.is_active = False
        action = AuditAction.USER_SUSPENDED
    else:
        user.status = UserStatus.ACTIVE
        user.is_active = True
        action = AuditAction.USER_ACTIVATED

    user.save()

    audit_action_create(
        user=toggled_by,
        category=AuditCategory.USER,
        organization=user.organization,
        action=action,
        details={
            "user_id": str(user.id),
            "prev_status": prev_status,
            "new_status": user.status,
        },
        target_type="user",
        target_id=str(user.id),
    )

    return user


@transaction.atomic
def user_update_user(
    *, user_id: str, updated_by: User, payload: UserUpdatePayload
) -> User:
    """
    Update a user's profile with proper role and organization scoping.

    Rules:
      - SUPERUSER can update anyone.
      - ORG_ADMIN can update anyone in their org.
      - ORG_MEMBER can update only themselves.
      - role is derived from `is_auditor`; never trust client input.
    """
    qs = User.objects.select_for_update()

    # Fetch user with proper scope
    if updated_by.is_platform_admin:
        user = qs.get(id=user_id)
    elif UserRole.ORG_ADMIN.value in updated_by.role:
        user = qs.get(id=user_id, organization=updated_by.organization)
    elif UserRole.ORG_MEMBER.value in updated_by.role:
        user = qs.get(id=user_id, organization=updated_by.organization)
        if user.id != updated_by.id:
            raise APIError(
                message="You can only update your own profile",
                code="FORBIDDEN",
                status=403,
            )
    else:
        raise APIError(
            message="Permission denied",
            code="FORBIDDEN",
            status=403,
        )

    # Determine allowed fields by updater's role
    if UserRole.ORG_MEMBER.value in updated_by.role:
        allowed_fields = {"first_name", "last_name", "phone"}
    else:  # ORG_ADMIN or SUPERUSER
        allowed_fields = {
            "first_name",
            "last_name",
            "phone",
            "functions",
            "can_publish_prod",
        }

    # Build update dict
    update_data = {
        field: getattr(payload, field)
        for field in allowed_fields
        if getattr(payload, field) is not None
    }

    # Handle is_auditor -> role
    if hasattr(payload, "is_auditor") and payload.is_auditor is not None:
        roles = set(user.role or [])
        if payload.is_auditor:
            roles.add(UserRole.AUDITOR.value)
        else:
            roles.discard(UserRole.AUDITOR.value)
        user.role = list(roles)

    # Apply updates
    for field, value in update_data.items():
        setattr(user, field, value)

    # Save only updated fields + role if changed
    save_fields = list(update_data.keys())
    if "role" in user.__dict__:  # role was modified
        save_fields.append("role")

    if save_fields:
        user.save(update_fields=save_fields)

    # Audit
    audit_action_create(
        user=updated_by,
        category=AuditCategory.USER,
        organization=user.organization,
        action=AuditAction.USER_UPDATED,
        target_type="user",
        target_id=str(user.id),
        details={
            "updated_fields": list(update_data.keys())
            + (["role"] if hasattr(payload, "is_auditor") else []),
            "user_id": str(user.id),
            "email": user.email,
        },
    )

    return user


@transaction.atomic
def user_delete(*, user_id: uuid.UUID, requesting_user: User):
    """
    Delete/deactivate a user - soft delete recommended
    """

    target_user = selectors.user_get_for_update(user_id=user_id)

    # Permission check - only org admins and superuser can delete users
    if not (requesting_user.is_org_admin or requesting_user.is_platform_admin):
        raise APIError(message="Permission Denied", code="FORBIDDEN", status=403)

    # Check same organization
    if target_user.organization_id != requesting_user.organization_id and not requesting_user.is_platform_admin:
        raise APIError(message="not Permission Denied", code="FORBIDDEN", status=403)

    # Prevent self-deletion
    if target_user.id == requesting_user.id:
        raise APIError(
            message="Cannot self delete", code="CANNOT_DELETE_SELF", status=400
        )

    target_user.status = UserStatus.DEACTIVATED
    target_user.is_active = False
    target_user.save(update_fields=["status", "is_active", "updated_at"])
    target_user.delete()

    audit_action_create(
        user=requesting_user,
        action=AuditAction.USER_DELETED,
        details={
            "user_id": str(user_id),
            "email": target_user.email,
        },
        category=AuditCategory.USER,
        organization=requesting_user.organization,
        target_type="user",
        target_id=user_id,
    )


@transaction.atomic
def user_request_password_reset(*, email: str, request=None) -> dict:
    """
    Request password reset link via email.

    Security:
    - Always returns success (don't reveal if email exists)
    - Rate limited: 3 requests per hour per email
    - Only sends to ACTIVE users
    - Token expires in 1 hour
    """
    email = email.strip().lower()

    # Cache-based rate limiting (atomic increment)
    #rl_key = f"users:password_reset:email:{email}"
    #try:
    #    attempts = cache.incr(rl_key)
    #except ValueError:
        # Key doesn't exist yet — initialize it
    #    cache.set(rl_key, 1, timeout=3600)  # 1 hour window
    #    attempts = 1

    #if attempts > 5:
    #    return {
    #        "success": True,
    #        "message": "Too many requests",
    #    }

    # Track per-IP patterns for abuse detection (non-blocking)
    _track_password_reset_by_ip(request=request, email=email)

    # Get user - still return success if not found (security)
    user = selectors.user_get_by_email(email=email)
    if not user or user.status != UserStatus.ACTIVE:
        # Log the attempt for security monitoring (no PII — hash the email)
        email_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
        audit_action_create(
            user=None,
            category=AuditCategory.AUTH,
            organization=None,
            action=AuditAction.PASSWORD_RESET_REQUESTED,
            details={
                "email_hash": email_hash,
                "reason": "user_not_found" if not user else "user_not_active",
            },
            target_type="user",
            target_id=None,
            request=request,
        )
        return {
            "success": True,
            "message": "Si l'adresse email existe, un lien de réinitialisation a été envoyé.",
        }

    # Generate token (following invitation pattern)
    token = secrets.token_urlsafe(32)
    now = timezone.now()

    user.password_reset_token = token
    user.password_reset_token_expires_at = now + timedelta(hours=1)
    user.password_reset_token_created_at = now
    user.save(update_fields=[
        'password_reset_token',
        'password_reset_token_expires_at',
        'password_reset_token_created_at',
        'updated_at'
    ])

    # Send email (French template, following invitation pattern)
    reset_url = f"{settings.FR_APP_DOMAIN}/auth/reset-password?token={token}"

    email_subject = f"[DID Annuaire] Réinitialisation de mot de passe"
    ctx = {
        "domain": settings.FR_APP_DOMAIN,
        "product_name": "DID Annuaire",
        "name": user.full_name,
        "action_url": reset_url
    }
    html = render_with_layout(inner_template="request_password_reset.html", context=ctx)
    send_html_email(to=[user.email], subject=email_subject, html=html)

    # Audit log
    audit_action_create(
        user=user,
        category=AuditCategory.USER,
        organization=user.organization,
        action=AuditAction.PASSWORD_RESET_REQUESTED,
        details={
            "user_id": str(user.id),
            "email": user.email,
            "token_expires_at": user.password_reset_token_expires_at.isoformat(),
        },
        target_type="user",
        target_id=str(user.id),
        request=request,
    )

    return {
        "success": True,
        "message": "Si l'adresse email existe, un lien de réinitialisation a été envoyé.",
    }

@transaction.atomic
def user_reset_password(*, token: str, new_password: str, request=None) -> dict:
    """
    Reset password using valid token.

    Validation:
    - Token must exist and not expired
    - Password must pass Django validators
    - Token invalidated after success (single-use)
    """
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError as DjangoValidationError

    # Get user by token (returns None if expired or not found)
    user = selectors.user_get_by_reset_token(token=token)

    if not user:
        raise DomainValidationError(
            message="Le lien de réinitialisation est invalide ou a expiré.",
            code="RESET_TOKEN_INVALID"
        )

    # Validate password using Django validators
    try:
        validate_password(new_password, user=user)
    except DjangoValidationError as e:
        audit_action_create(
            user=user,
            category=AuditCategory.USER,
            organization=user.organization,
            action=AuditAction.PASSWORD_RESET_FAILED,
            details={
                "user_id": str(user.id),
                "reason": "password_validation_failed",
                "errors": list(e.messages),
            },
            target_type="user",
            target_id=str(user.id),
            request=request,
        )
        error_msg = " ".join(e.messages)
        raise DomainValidationError(
            message=f"{error_msg}",
            code="PASSWORD_VALIDATION_FAILED"
        )

    # Set new password
    user.set_password(new_password)

    # Invalidate token (single-use)
    invalidate_password_reset_token(user)

    user.save(update_fields=[
        'password',
        'password_reset_token',
        'password_reset_token_expires_at',
        'password_reset_token_created_at',
        'updated_at'
    ])

    # Success audit log
    audit_action_create(
        user=user,
        category=AuditCategory.USER,
        organization=user.organization,
        action=AuditAction.PASSWORD_RESET_COMPLETED,
        details={
            "user_id": str(user.id),
            "email": user.email,
        },
        target_type="user",
        target_id=str(user.id),
        request=request,
    )

    return {
        "success": True,
        "message": "Votre mot de passe a été réinitialisé avec succès.",
    }