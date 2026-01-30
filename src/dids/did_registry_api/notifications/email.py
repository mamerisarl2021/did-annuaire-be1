from typing import Iterable, Any
from urllib.parse import urljoin

from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from src.emails.services import email_send
from src.dids.models import PublishRequest
from src.users.models import User, UserRole

DEFAULT_LAYOUT = "email_default_layout.html"


def _render_with_layout(inner_template: str | None, context: dict[str, Any]) -> str:
    """
    Enveloppe l'email dans le layout par défaut. Si 'inner_template' est fourni,
    on le rend d'abord puis on l'injecte dans le layout via {{ content|safe }}.
    """
    if inner_template:
        content_html = render_to_string(inner_template, context)
        outer_ctx = dict(context)
        outer_ctx["content"] = content_html
        return render_to_string(DEFAULT_LAYOUT, outer_ctx)

    # Pas de template interne: on s'attend à ce que 'content' soit dans le contexte
    return render_to_string(DEFAULT_LAYOUT, context)


def _send_html_email(to: Iterable[str], subject: str, html: str, text_fallback: str | None = None,
                     cc: Iterable[str] | None = None, bcc: Iterable[str] | None = None) -> None:

    text = text_fallback or strip_tags(html)

    email_send(to=list(to), subject=subject, html=html, text=text, cc=list(cc) if cc else None,
               bcc=list(bcc) if bcc else None)


def _org_admin_emails(org) -> list[str]:
    """
    Renvoie les emails des ORG_ADMIN d'une organisation. Adapte le filtre à ton modèle.
    """
    try:
        qs = User.objects.filter(organization=org, role=UserRole.ORG_ADMIN, is_active=True).only("email")
        return [u.email for u in qs if u.email]
    except Exception:
        # Fallback: aucun destinataire
        return []


def send_publish_request_notification(pr: PublishRequest) -> None:
    """
    Notifie les ORG_ADMIN qu'une demande de publication PROD a été créée.
    """
    org = pr.did.organization
    recipients = _org_admin_emails(org)
    if not recipients:
        return

    did = pr.did.did
    subject = f"[DID Annuaire] Demande de publication PROD pour {did}"
    ctx = {
        "title": "Demande de publication en production",
        "org_name": org.name if hasattr(org, "name") else "—",
        "did": did,
        "version": pr.did_document.version,
        "requested_by": getattr(pr.requested_by, "email", None),
        "environment": pr.environment.upper(),
        "publish_request_id": pr.id,
        "admin_url": urljoin(
            settings.FR_APP_DOMAIN,
            "/dashboard/publish-requests",
        ),
    }
    html = _render_with_layout(inner_template="templates/publish_request_content.html",context=ctx,)
    _send_html_email(to=recipients, subject=subject, html=html)


def send_publish_decision_notification(pr: PublishRequest) -> None:
    """
    Notifie le demandeur que la demande a été approuvée ou rejetée.
    """
    to_email = getattr(pr.requested_by, "email", None)
    if not to_email:
        return

    did = pr.did.did
    approved = (pr.status == PublishRequest.Status.APPROVED)
    subject = f"[DID Annuaire] Publication PROD {'approuvée' if approved else 'rejetée'} pour {did}"


    ctx = {
            "title": "Décision de publication",
            "did": did,
            "version": pr.did_document.version,
            "requested_by": getattr(pr.requested_by, "email", "Utilisateur"),
            "status": "APPROVED" if pr.status == PublishRequest.Status.APPROVED else "REJECTED",
            "note": pr.note.strip() if pr.note else "",
            "dashboard_url": urljoin(settings.FR_APP_DOMAIN, "/dashboard/publish-requests"),
        }
    html = _render_with_layout(inner_template="emails/publish_decision_content.html", context=ctx)
    _send_html_email(to=[to_email], subject=subject, html=html)
