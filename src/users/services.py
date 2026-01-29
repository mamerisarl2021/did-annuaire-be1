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

def verify_otp(*, user: User, otp_type: Literal["email", "sms", "totp"], provided_code: str) -> bool:
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
                code="OTP_NOT_GENERATED"
            )

        if timezone.now() > expires_at:
            raise DomainValidationError(
                message=f"{otp_type.upper()} OTP expired",
                code="OTP_EXPIRED"
            )

        if stored_code != provided_code:
            raise DomainValidationError(
                message=f"{otp_type.upper()} OTP invalid",
                code="OTP_INVALID"
            )

        setattr(user, code_field, "")
        setattr(user, expires_field, None)
        user.save()
        return True

    if otp_type == "totp":
        if not user.totp_secret:
            raise DomainValidationError(
                message="TOTP not prepared",
                code="TOTP_REQUIRED"
            )
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(provided_code, valid_window=1):
            raise DomainValidationError(
                message="TOTP code invalid",
                code="TOTP_INVALID"
            )
        return True

    raise ValueError(f"Unsupported OTP type: {otp_type}")
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
    can_publish_prod: bool = True
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
        can_publish_prod=can_publish_prod
    )

    audit_action_create(
        user=created_by,
        category=AuditCategory.USER,
        organization=organization,
        action=AuditAction.USER_CREATED,
        details={"user_id": user.id, "email": email, "role": roles, "publish authorization": can_publish_prod},
        target_type="user",
        target_id=str(user.id)
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
        message="Veuillez patienter avant de renvoyer l’invitation.",
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
def user_activate_account(*, token: str, password: str, enable_totp: bool = False) -> User:
    user = user_get_invited_by_token(token=token)
    user.set_password(password)
    user.status = UserStatus.ACTIVE
    user.invitation_accepted_at = timezone.now()
    user.invitation_token = ""
    if enable_totp:
        user.totp_enabled = True
    user.is_active = True
    user.save()
    audit_action_create(
        user=user,  # actor: here it is the user themselves
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
            message="OTP not allowed for active user",
            code="OTP_NOT_ALLOWED"
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
            message=f"Veuillez patienter avant de redemander un {otp_type.upper()} code."
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
            html=f"<p>Votre code de vérification est: <strong>{code}</strong></p><p>Valide pendant 10 minutes.</p>"
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
        details={"user_id": str(user.id), "prev_status": prev_status, "new_status": user.status},
        target_type="user",
        target_id=str(user.id),
    )

    return user


@transaction.atomic
def user_update_user(*, user_id: str, updated_by: User, payload: UserUpdatePayload) -> User:
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
        allowed_fields = {"first_name", "last_name", "phone", "functions", "can_publish_prod"}

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
            "updated_fields": list(update_data.keys()) + (["role"] if hasattr(payload, "is_auditor") else []),
            "user_id": str(user.id),
            "email": user.email,
        },
    )

    return user
    