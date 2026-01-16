import secrets
import io
import base64
import uuid
from datetime import timedelta

import pyotp
import qrcode

from django.db import transaction
from django.utils import timezone

from src.auditaction.models import AuditAction
from src.core.exceptions import DomainValidationError
from src.core.ratelimit import enforce_min_interval
from src.users.models import User, UserStatus
from src.emails.services import email_send
from src.auditaction.services import audit_action_create


@transaction.atomic
def user_create_by_admin(*, organization, created_by: User, email: str, first_name: str, last_name: str, phone: str,
                         role: str, functions: str | None = None) -> User:
    """Admin org crée un utilisateur"""
    user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name, phone=phone,
                                    organization=organization, role=role, status=UserStatus.PENDING,
                                    invited_by=created_by, functions=functions or "", )
    audit_action_create(user=created_by, action=AuditAction.USER_CREATED,
                        details={"user_id": user.id, "email": email, "role": role}, )
    return user


@transaction.atomic
def user_send_invitation(*, user: User, invited_by: User):
    """Envoyer invitation à un utilisateur"""
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

    activation_url = f"http://localhost:8000/activate?token={token}"
    email_send(
        to=[user.email],
        subject=f"Invitation - {user.organization.name if user.organization else 'DID Annuaire'}",
        html=f"""
            <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; border: 1px solid #ddd; border-radius: 8px; max-width: 600px; margin: auto;">
                <h2 style="color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px;">Bienvenue !</h2>
                <p>Vous avez été invité à rejoindre <strong>{user.organization.name if user.organization else 'DID Annuaire'}</strong>.</p>
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
    audit_action_create(user=user.invited_by,
                        action=AuditAction.USER_INVITED,
                        details={"user_id": user.id, "email": user.email}, )

def user_get_invited_by_token(*, token: str) -> User:
    try:
        user = User.objects.get(invitation_token=token, status=UserStatus.INVITED)
    except User.DoesNotExist:
        raise DomainValidationError(message="Lien invalide", code="INVITE_INVALID")
    if user.invitation_sent_at and user.invitation_sent_at < timezone.now() - timedelta(days=7):
        raise DomainValidationError(message="Le lien d'activation a expiré", code="INVITE_EXPIRED")
    return user

def user_verify_totp_or_raise(*, user: User, code: str) -> None:
    if not user.totp_secret:
        raise DomainValidationError(message="TOTP non préparé", code="TOTP_REQUIRED")
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        raise DomainValidationError(message="Code TOTP invalide", code="TOTP_INVALID")



@transaction.atomic
def user_activate_account(*, token: str, password: str, enable_totp: bool = False) -> User:
    """
    Finalise l’activation. Ne génère PAS de secret TOTP.
    Supposé que le secret existe déjà si enable_totp=True (vérifié avant).
    """
    user = user_get_invited_by_token(token=token)
    user.set_password(password)
    user.status = UserStatus.ACTIVE
    user.invitation_accepted_at = timezone.now()
    user.invitation_token = ""
    if enable_totp:
        # activer le flag; le secret doit déjà exister et avoir été vérifié avant
        user.totp_enabled = True
    user.is_active = True
    user.save()
    audit_action_create(user=user, action=AuditAction.USER_ACTIVATED, details={"user_id": user.id})
    return user



def user_generate_totp_qr(*, user: User) -> str:
    """Générer QR code pour Google Authenticator"""
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="DID Annuaire")

    qr = qrcode.QRCode(version=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_L,
                       box_size=10,
                       border=4, )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"


def user_verify_totp(*, user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code, valid_window=1)


@transaction.atomic
def user_generate_email_otp(*, user: User) -> str:
    last_sent = (
        user.email_otp_expires_at - timedelta(minutes=10)
        if user.email_otp_expires_at else None
    )
    enforce_min_interval(
        last_sent,
        seconds=120,
        code="OTP_RATE_LIMIT",
        message="Veuillez patienter avant de redemander un code.",
    )

    code = str(secrets.randbelow(1000000)).zfill(6)
    user.email_otp_code = code
    user.email_otp_expires_at = timezone.now() + timedelta(minutes=10)
    user.save()

    email_send(
        to=[user.email],
        subject="Code de vérification",
        html=f"<p>Votre code de vérification est: <strong>{code}</strong></p><p>Valide pendant 10 minutes.</p>",
    )
    return code


def _verify_otp_helper(user, otp_code_field: str, otp_expires_field: str, provided_code: str) -> bool:
    stored_code = getattr(user, otp_code_field, None)
    expires_at = getattr(user, otp_expires_field, None)
    if not stored_code or not expires_at:
        return False
    if timezone.now() > expires_at:
        raise DomainValidationError(message="OTP expired", code="OTP_EXPIRED")
    if stored_code != provided_code:
        raise DomainValidationError(message="OTP invalid", code="OTP_INVALID")

    setattr(user, otp_code_field, "")
    setattr(user, otp_expires_field, None)
    user.save()
    return True


def user_verify_email_otp(*, user: User, code: str) -> bool:
    return _verify_otp_helper(user, "email_otp_code", "email_otp_expires_at", code)


@transaction.atomic
def user_generate_sms_otp(*, user: User) -> str:
    last_sent = (
        user.sms_otp_expires_at - timedelta(minutes=10)
        if user.sms_otp_expires_at else None
    )
    enforce_min_interval(
        last_sent,
        seconds=60,
        code="OTP_RATE_LIMIT",
        message="Veuillez patienter avant de redemander un code.",
    )

    code = str(secrets.randbelow(1000000)).zfill(6)
    user.sms_otp_code = code
    user.sms_otp_expires_at = timezone.now() + timedelta(minutes=10)
    user.save()
    return code


def user_verify_sms_otp(*, user: User, code: str) -> bool:
    return _verify_otp_helper(user, "sms_otp_code", "sms_otp_expires_at", code)


@transaction.atomic
def user_resend_invitation(*, user_id: uuid.UUID, requested_by: User) -> User:
    user = User.objects.get(id=user_id)
    # Only for users not active yet
    if user.status == UserStatus.ACTIVE:
        raise DomainValidationError(message="User already active", code="INVITE_NOT_ALLOWED")

    enforce_min_interval(
        user.invitation_sent_at,
        seconds=120,
        code="INVITE_RATE_LIMIT",
        message="Veuillez patienter avant de renvoyer l’invitation.",
    )

    token = secrets.token_urlsafe(32)
    user.invitation_token = token
    user.invitation_sent_at = timezone.now()
    user.status = UserStatus.INVITED
    user.save()

    activation_url = f"http://localhost:8000/activate?token={token}"
    email_send(
        to=[user.email],
        subject=f"Invitation - {user.organization.name if user.organization else 'DID Annuaire'}",
        html=f"""<p>Nouvelle invitation pour {user.email}.</p>
                 <p><a href="{activation_url}">Activer le compte</a> (expire dans 7 jours)</p>"""
    )

    audit_action_create(
        user=requested_by, action=AuditAction.USER_INVITED,
        details={"user_id": str(user.id), "email": user.email, "resend": True}
    )
    return user


@transaction.atomic
def user_deactivate(*, user_id: uuid.UUID, deactivated_by: User) -> User:
    """Désactiver un utilisateur"""
    user = User.objects.get(id=user_id)
    user.status = UserStatus.DEACTIVATED  # no trailing comma
    user.is_active = False
    user.save()
    audit_action_create(
        user=deactivated_by,
        action=AuditAction.USER_DEACTIVATED,
        details={"user_id": user.id, "email": user.email},
    )
    return user


@transaction.atomic
def user_update(
        *,
        user_id: uuid.UUID,
        updated_by: User,
        first_name: str | None = None,
        last_name: str | None = None,
        phone: str | None = None,
        role: str | None = None,
        functions: str | None = None,
        status: str | None = None,
) -> User:
    """Mettre à jour un utilisateur (champs optionnels)."""
    user = User.objects.get(id=user_id)

    # Minimal policy examples (adjust as needed):
    # - Only ORG_ADMIN/SUPERUSER can change role/status
    from src.users.models import UserRole as UR
    if role is not None or status is not None:
        if getattr(updated_by, "role", None) not in (UR.ORG_ADMIN, UR.SUPERUSER):
            raise ValueError("Permission denied to change role/status")

    if first_name is not None:
        user.first_name = first_name
    if last_name is not None:
        user.last_name = last_name
    if phone is not None:
        user.phone = phone
    if role is not None:
        user.role = role
    if functions is not None:
        user.functions = functions
    if status is not None:
        user.status = status
        if status == UserStatus.ACTIVE:
            user.is_active = True
        if status == UserStatus.DEACTIVATED:
            user.is_active = False

    user.save()
    audit_action_create(
        user=updated_by,
        action=AuditAction.USER_UPDATED,
        details={"user_id": user.id},
    )
    return user
