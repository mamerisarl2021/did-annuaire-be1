from django.conf import settings
from django.db import transaction
from django.utils.text import slugify

from src.common.notifications.email import render_with_layout, send_html_email
from src.auditaction.models import AuditAction, AuditCategory
from src.core.exceptions import DomainConflictError
from src.organizations.models import Organization, OrganizationStatus
from src.users.models import User, UserStatus, UserRole
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

    # Create Organization
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

    # Create admin
    admin = User.objects.create_user(
        email=admin_email,
        first_name=admin_first_name,
        last_name=admin_last_name,
        phone=admin_phone,
        organization=org,
        functions=functions,
        role=[UserRole.ORG_ADMIN],
        status=UserStatus.PENDING,
    )

    # Notifier les super admins
    _notify_super_admins_new_org(org)

    # Notifier l'admin que sa demande est en cours d'examen
    _notify_admin_pending_review(org=org, admin=admin)

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


def _notify_super_admins_new_org(org: Organization):
    """Notifier les super admins d'une nouvelle organisation"""
    super_admins = User.objects.filter(is_superuser=True, is_active=True)
    emails = [admin.email for admin in super_admins]

    if not emails:
        return

    ctx = {
        "title": "Nouvelle demande d'inscription",
        "org_name": org.name,
        "org_type": org.get_type_display(),
        "org_country": org.country,
        "org_email": org.email,
        "admin_url": f"{settings.FR_APP_DOMAIN}/dashboard/superuser",
    }
    html = render_with_layout(inner_template="new_organization_pending.html", context=ctx)
    send_html_email(
        to=emails,
        subject=f"[DID Annuaire] Nouvelle organisation : {org.name} — Action requise",
        html=html,
    )

def _notify_admin_pending_review(*, org: Organization, admin: User):
    """Notifier l'admin que l'organisation est en attente de validation"""
    if not admin.email:
        return

    status_url = f"{settings.FR_APP_DOMAIN}/auth/register/status?organizationId={org.id}&organizationName={org.name}"
    admin_name = admin.full_name if hasattr(admin, "full_name") and admin.full_name else None

    ctx = {
        "title": "Demande d'inscription enregistrée",
        "admin_name": admin_name,
        "org_name": org.name,
        "org_type": org.get_type_display(),
        "org_email": org.email,
        "status_url": status_url,
    }
    html = render_with_layout(inner_template="organization_pending_review.html", context=ctx)
    send_html_email(
        to=[admin.email],
        subject=f"[DID Annuaire] Demande enregistrée — {org.name}",
        html=html,
    )