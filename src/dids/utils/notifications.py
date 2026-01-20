from __future__ import annotations
from django.conf import settings
from django.core.mail import send_mail, mail_admins


def _safe_from_email() -> str:
    return getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@localhost")


def _user_email(user) -> str:
    return getattr(user, "email", None) or ""


def _org_admin_emails(organization) -> list[str]:
    """
    Tente d'extraire l'email des ORG_ADMIN de l'organisation.
    Adapté à plusieurs schémas (org.users, FK inversée, etc.).
    """
    try:
        from src.users.models import User, UserRole
    except Exception:
        # Fallback: si pas d'accès aux modèles, renvoie admins système
        admins = getattr(settings, "ADMINS", [])
        return [e for _, e in admins]

    emails: list[str] = []

    # Cas 1: relation m2m/défaut: organization.users
    users_qs = getattr(organization, "users", None)
    if users_qs is not None and hasattr(users_qs, "filter"):
        qs = users_qs.filter(role=UserRole.ORG_ADMIN)
        emails.extend([_user_email(u) for u in qs if _user_email(u)])

    # Cas 2: relation FK: User.objects.filter(organization=org)
    if not emails and hasattr(User, "objects"):
        try:
            qs = User.objects.filter(organization=organization, role=UserRole.ORG_ADMIN)
            emails.extend([_user_email(u) for u in qs if _user_email(u)])
        except Exception:
            pass

    # Fallback: ADMINS settings
    if not emails:
        admins = getattr(settings, "ADMINS", [])
        emails = [e for _, e in admins]

    # Unicité
    return sorted(set(emails))


def send_publish_request_notification(publish_request) -> None:
    """
    Notifie les ORG_ADMIN qu'une demande de publication PROD est en attente.
    """
    org = publish_request.did.organization
    subject = f"[DID Registry] Demande de publication PROD — {publish_request.did.did} v{publish_request.did_document.version}"
    body = (
        f"Bonjour,\n\n"
        f"Une demande de publication en PROD a été soumise.\n\n"
        f"DID: {publish_request.did.did}\n"
        f"Version: {publish_request.did_document.version}\n"
        f"Environnement: {publish_request.environment}\n"
        f"Demandé par: {getattr(publish_request.requested_by, 'email', 'unknown')}\n"
        f"ID de la demande: {publish_request.id}\n\n"
        f"Veuillez approuver ou rejeter la demande via l’interface d’administration.\n"
    )
    recipients = _org_admin_emails(org)
    if recipients:
        try:
            send_mail(subject, body, _safe_from_email(), recipients, fail_silently=True)
        except Exception:
            mail_admins(subject, body, fail_silently=True)


def send_publish_decision_notification(publish_request) -> None:
    """
    Notifie le demandeur de la décision (APPROVED/REJECTED).
    """
    subject = f"[DID Registry] Décision publication {publish_request.status} — {publish_request.did.did} v{publish_request.did_document.version}"
    body = (
        f"Bonjour,\n\n"
        f"Votre demande de publication a été {publish_request.status}.\n\n"
        f"DID: {publish_request.did.did}\n"
        f"Version: {publish_request.did_document.version}\n"
        f"Environnement: {publish_request.environment}\n"
        f"Décidé par: {getattr(publish_request.decided_by, 'email', 'unknown')}\n"
        f"Note: {publish_request.note or '-'}\n"
    )
    recipient = _user_email(publish_request.requested_by)
    if recipient:
        try:
            send_mail(
                subject, body, _safe_from_email(), [recipient], fail_silently=True
            )
        except Exception:
            mail_admins(
                subject, f"(Delivery to requester failed)\n\n{body}", fail_silently=True
            )
