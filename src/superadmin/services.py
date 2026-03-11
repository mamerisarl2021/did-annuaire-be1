import secrets
from uuid import UUID

from django.conf import settings
from django.utils import timezone
from django.db import transaction

from src.common.notifications.email import render_with_layout, send_html_email
from src.users.models import User, UserRole, UserStatus
from src.organizations.models import Organization, OrganizationStatus
from src.auditaction.services import audit_action_create
from src.auditaction.models import AuditCategory, AuditAction, Severity
from src.core.exceptions import DomainConflictError


def _notify_org_admin_decision(
    *,
    org: Organization,
    status: str,
    reason: str = "",
    action_url: str = "",
) -> None:
    """
    Send a validation/refusal decision email to the org's admin.
    Uses a single dynamic template for both outcomes.

    Args:
        org: The organization
        status: "VALIDATED" or "REFUSED"
        reason: Refusal reason (only for REFUSED)
        action_url: Account activation link (only for VALIDATED)
    """
    admin = (
        org.users.filter(role__contains=[UserRole.ORG_ADMIN])
        .order_by("created_at", "id")
        .first()
    )
    if not admin:
        return

    status_labels = {
        "VALIDATED": "validée",
        "REFUSED": "refusée",
    }
    label = status_labels.get(status, status.lower())

    ctx = {
        "title": f"Inscription {label} — {org.name}",
        "org_name": org.name,
        "status": status,
        "reason": reason,
        "action_url": action_url,
        "contact_email": getattr(settings, "SUPPORT_EMAIL", ""),
    }
    html = render_with_layout(
        inner_template="organization_validate_decision.html", context=ctx
    )
    send_html_email(
        to=[admin.email],
        subject=f"[DID Annuaire] Inscription {label} — {org.name}",
        html=html,
    )


@transaction.atomic
def organization_validate(*, organization_id: UUID, validated_by: User) -> Organization:
    org = Organization.objects.get(id=organization_id)

    if org.status != OrganizationStatus.PENDING:
        raise DomainConflictError(
            message="Organization cannot be validated in its current state",
            code="ORG_INVALID_STATUS",
            errors={"status": [org.status]},
        )
    # Activate Organization
    org.status = OrganizationStatus.ACTIVE
    org.validated_at = timezone.now()
    org.validated_by = validated_by
    org.save(update_fields=["status", "validated_at", "validated_by"])

    # Prepare invitation for admin
    admin = (
        org.users.filter(role__contains=[UserRole.ORG_ADMIN])
        .order_by("created_at", "id")
        .first()
    )

    action_url = ""
    if admin:
        # Generate invitation token (same logic as user_send_invitation)
        token = secrets.token_urlsafe(32)
        admin.invitation_token = token
        admin.invitation_sent_at = timezone.now()
        admin.invited_by = validated_by
        admin.status = UserStatus.INVITED
        admin.save(update_fields=[
            "invitation_token",
            "invitation_sent_at",
            "invited_by",
            "status",
            "updated_at",
        ])

        action_url = f"{settings.FR_APP_DOMAIN}/activate?token={token}"

        audit_action_create(
            user=validated_by,
            category=AuditCategory.USER,
            organization=org,
            action=AuditAction.USER_INVITED,
            details={"user_id": str(admin.id), "email": admin.email},
            target_type="user",
            target_id=str(admin.id),
        )
    else:
        audit_action_create(
            user=validated_by,
            action=AuditAction.ADMIN_NOT_FOUND,
            details={
                "organization_id": str(org.id),
                "note": "No user with ORG_ADMIN role",
            },
            category=AuditCategory.ORGANIZATION,
            organization=org,
            target_type="organization",
            target_id=org.id,
            severity=Severity.INFO,
        )

    # Send decision email (includes activation link if admin exists)
    _notify_org_admin_decision(org=org, status="VALIDATED", action_url=action_url)

    audit_action_create(
        user=validated_by,
        action=AuditAction.ORG_VALIDATED,
        details={"organization_id": str(org.id), "organization_name": org.name},
        category=AuditCategory.ORGANIZATION,
        organization=org,
        target_type="organization",
        target_id=org.id,
    )

    return org


@transaction.atomic
def organization_refuse(
    *, organization_id: UUID, refused_by: User, reason: str
) -> Organization:
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

    # Notify admin of refusal
    _notify_org_admin_decision(org=org, status="REFUSED", reason=reason)

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
def organization_toggle_activation(
    *, organization_id: str, toggled_by: User
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