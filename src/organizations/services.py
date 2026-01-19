from __future__ import annotations

import uuid

from django.conf import settings
from django.db import transaction
from django.utils.text import slugify
from django.utils import timezone

from src.auditaction.models import AuditAction, AuditCategory
from src.core.exceptions import DomainConflictError
from src.organizations.models import Organization, OrganizationStatus
from src.users.models import User, UserStatus, UserRole
from src.users.services import user_send_invitation
from src.emails.services import email_send
from src.auditaction.services import audit_action_create


@transaction.atomic
def organization_create(
    *,
    name: str,
    org_type: str,
    country: str,
    email: str,
    phone: str,
    address: str,
    allowed_email_domains: list[str],
    admin_email: str,
    admin_first_name: str,
    admin_last_name: str,
    admin_phone: str,
    functions: str,
    authorization_document,
    justification_document=None,
) -> Organization:
    """Créer une nouvelle organisation (en attente de validation)"""

    slug = slugify(name)

    # Vérifier unicité
    if Organization.objects.filter(slug=slug).exists():
        raise DomainConflictError(
            message="Organization name is not available",
            code="ORG_NAME_TAKEN",
            errors={"name": ["already taken"]},
        )
    if Organization.objects.filter(email=email).exists():
        raise DomainConflictError(
            message="Organization email already in use",
            code="ORG_EMAIL_TAKEN",
            errors={"email": ["already taken"]},
        )
    if User.objects.filter(email=admin_email).exists():
        raise DomainConflictError(
            message="Admin email already in use",
            code="ADMIN_EMAIL_TAKEN",
            errors={"admin_email": ["already taken"]},
        )

    # Créer l'organisation
    org = Organization.objects.create(
        name=name,
        slug=slug,
        type=org_type,
        country=country,
        email=email,
        phone=phone,
        address=address,
        allowed_email_domains=allowed_email_domains,
        authorization_document=authorization_document,
        justification_document=justification_document or None,
        status=OrganizationStatus.PENDING,
    )

    # Créer l'admin (statut PENDING)
    admin = User.objects.create_user(
        email=admin_email,
        first_name=admin_first_name,
        last_name=admin_last_name,
        phone=admin_phone,
        organization=org,
        functions=functions,
        role=UserRole.ORG_ADMIN,
        status=UserStatus.PENDING,
    )

    # Notifier les super admins
    _notify_super_admins_new_org(org)

    # Audit
    audit_action_create(
        user=None,
        action=AuditAction.ORG_CREATED,
        details={
            "organization_id": org.id,
            "organization_name": org.name,
            "admin_email": admin_email,
        },
        category=AuditCategory.ORGANIZATION,
    )

    return org


@transaction.atomic
def organization_delete(*, organization_id: uuid.UUID, deleted_by: User) -> None:
    org = Organization.objects.get(id=organization_id)
    org_name = org.name
    org_id = org.id
    org.delete()  # hard delete; ensure FK cascades are intended
    audit_action_create(
        user=deleted_by,
        action=AuditAction.ORG_SUSPENDED,
        details={"organization_id": str(org_id), "organization_name": org_name},
        category=AuditCategory.ORGANIZATION,
    )


@transaction.atomic
def organization_toggle_activation(
    *, organization_id: uuid.UUID, toggled_by: User
) -> Organization:
    org = Organization.objects.get(id=organization_id)
    if org.status == OrganizationStatus.ACTIVE:
        org.status = OrganizationStatus.SUSPENDED
    elif org.status == OrganizationStatus.SUSPENDED:
        org.status = OrganizationStatus.ACTIVE
    else:
        raise ValueError(f"Only ACTIVE/SUSPENDED can be toggled (current={org.status})")
    org.save(update_fields=["status", "updated_at"])
    audit_action_create(
        user=toggled_by,
        action=AuditAction.ORGANIZATION_TOGGLED_ACTIVATION,
        details={"organization_id": str(org.id), "new_status": org.status},
        category="ORGANIZATION",
    )
    return org


@transaction.atomic
def organization_validate(
    *, organization_id: uuid.UUID, validated_by: User
) -> Organization:
    """Super admin valide une organisation"""

    org = Organization.objects.get(id=organization_id)

    if org.status != OrganizationStatus.PENDING:
        raise ValueError(f"Cannot validate organization with status {org.status}")

    # Valider
    org.status = OrganizationStatus.ACTIVE
    org.validated_at = timezone.now()
    org.validated_by = validated_by
    org.save()

    # Envoyer invitation à l'admin
    admin = org.users.filter(role=UserRole.ORG_ADMIN).first()
    if admin:
        user_send_invitation(user=admin, invited_by=validated_by)

    # Audit
    audit_action_create(
        user=validated_by,
        action=AuditAction.ORG_VALIDATED,
        details={"organization_id": org.id, "organization_name": org.name},
    )

    return org


@transaction.atomic
def organization_refuse(
    *, organization_id: uuid.UUID, refused_by: User, reason: str
) -> Organization:
    """Super admin refuse une organisation"""

    org = Organization.objects.get(id=organization_id)

    if org.status != OrganizationStatus.PENDING:
        raise ValueError(f"Cannot refuse organization with status {org.status}")

    org.status = OrganizationStatus.REFUSED
    org.refused_at = timezone.now()
    org.refused_by = refused_by
    org.refusal_reason = reason
    org.save()

    # Notifier l'admin
    admin = org.users.filter(role=UserRole.ORG_ADMIN).first()
    if admin:
        email_send(
            to=[admin.email],
            subject=f"Inscription refusée - {org.name}",
            html=f"""
                <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; border: 1px solid #ddd; border-radius: 8px; max-width: 600px; margin: auto;">
                    <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 10px;">Demande d'inscription refusée</h2>
                    <p>Votre demande d'inscription pour <strong>{org.name}</strong> a malheureusement été examinée et <strong>refusée</strong>.</p>
                    <p><strong>Raison du refus :</strong><br>{reason}</p>
                    <p>Nous vous invitons à corriger les points mentionnés ci-dessus et à soumettre une nouvelle demande lorsque cela sera possible.</p>
                    <p>Pour toute question ou clarification, n'hésitez pas à <a href="mailto:support@example.com" style="color: #0056b3; text-decoration: underline;">nous contacter</a>.</p>
                    <p style="font-size: 0.9em; color: #666; margin-top: 20px;">
                        Ce message est automatique. Merci de ne pas y répondre directement.
                    </p>
                </div>
            """,
        )

        # Audit
    audit_action_create(
        user=refused_by,
        action=AuditAction.ORG_REFUSED,
        details={
            "organization_id": org.id,
            "organization_name": org.name,
            "reason": reason,
        },
    )

    return org


# TODO: Organization Update


def _notify_super_admins_new_org(org: Organization):
    """Notifier les super admins d'une nouvelle organisation"""
    super_admins = User.objects.filter(role=UserRole.SUPERUSER, is_active=True)
    emails = [admin.email for admin in super_admins]

    if emails:
        email_send(
            to=emails,
            subject=f"Nouvelle organisation : {org.name} - Action requise",
            html=f"""
                <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; border: 1px solid #ddd; border-radius: 8px; max-width: 600px; margin: auto;">
                    <h2 style="color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px;">Nouvelle demande d'inscription</h2>
                    <p>Une nouvelle organisation a été enregistrée et attend votre validation.</p>
                    <ul style="list-style: none; padding: 0;">
                        <li><strong>Organisation :</strong> {org.name}</li>
                        <li><strong>Type :</strong> {org.get_type_display()}</li>
                        <li><strong>Pays :</strong> {org.country}</li>
                        <li><strong>Email :</strong> {org.email}</li>
                    </ul>
                    <p style="margin-top: 20px;">
                        <a href="{settings.FR_APP_DOMAIN}" 
                           style="background-color: #0056b3; color: white; padding: 8px 12px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Valider dans le panneau d'administration
                        </a>
                    </p>
                    <p style="font-size: 0.9em; color: #666; margin-top: 20px;">
                        Ce message est automatique. Merci de ne pas y répondre directement.
                    </p>
                </div>
            """,
        )
