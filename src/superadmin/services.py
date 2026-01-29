from uuid import UUID

from django.utils import timezone
from django.db import transaction

from src.emails.services import email_send
from src.users.models import User, UserRole
from src.users import services
from src.organizations.models import Organization, OrganizationStatus
from src.auditaction.services import audit_action_create
from src.auditaction.models import AuditCategory, AuditAction
from src.core.exceptions import DomainConflictError

@transaction.atomic
def organization_validate(*, organization_id: UUID, validated_by: User) -> Organization:
    org = Organization.objects.get(id=organization_id)

    if org.status != OrganizationStatus.PENDING:
        raise DomainConflictError(
            message="Organization cannot be validated in its current state",
            code="ORG_INVALID_STATUS",
            errors={"status": [org.status]},
        )
    # Valider
    org.status = OrganizationStatus.ACTIVE
    org.validated_at = timezone.now()
    org.validated_by = validated_by
    org.save()

    # Envoyer invitation à l'admin
    admin = org.users.filter(role=UserRole.ORG_ADMIN).first()
    if admin:
        services.user_send_invitation(user=admin, invited_by=validated_by)

    # Audit
    audit_action_create(
        user=validated_by,
        action=AuditAction.ORG_VALIDATED,
        details={
            "organization_id": org.id,
            "organization_name": org.name,
        },
        category=AuditCategory.ORGANIZATION,
        organization=org,
        target_type="organization",
        target_id=org.id,
    )

    return org

@transaction.atomic
def organization_refuse(*, organization_id: UUID, refused_by: User, reason: str) -> Organization:
    org = Organization.objects.get(id=organization_id)

    if org.status != OrganizationStatus.PENDING:
            raise DomainConflictError(
                message="Organization cannot be validated in its current state",
                code="ORG_INVALID_STATUS",
                errors={"status": [org.status]},
            )
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
        category=AuditCategory.ORGANIZATION,
        organization=org,
        target_type="organization",
        target_id=org.id,
    )

    return org


@transaction.atomic
def organization_toggle_activation(*, organization_id: str, toggled_by: User) -> Organization:
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
        category=AuditCategory.ORGANIZATION,
        organization=org,
        target_type="organization",
        target_id=org.id,
    )
    return org


@transaction.atomic
def organization_delete(*, organization_id: UUID, deleted_by: User) -> None:
    org = Organization.objects.get(id=organization_id)
    org_name = org.name
    org_id = org.id
    org.delete()  # hard delete; ensure FK cascades are intended
    audit_action_create(
        user=deleted_by,
        action=AuditAction.ORG_DELETED,
        details={"organization_id": str(org_id), "organization_name": org_name},
        category=AuditCategory.ORGANIZATION,
        target_type="organization",
    )

