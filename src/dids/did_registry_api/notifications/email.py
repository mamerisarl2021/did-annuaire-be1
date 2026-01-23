from typing import Iterable, Any
from src.emails.services import email_send


from django.template.loader import render_to_string
from django.utils.html import strip_tags

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
        "org_name": getattr(org, "name", str(org)),
        "did": did,
        "version": pr.did_document.version,
        "requested_by": getattr(pr.requested_by, "email", None),
        "environment": pr.environment,
        "publish_request_id": pr.id,
        # Le layout par défaut doit inclure {{ content|safe }}. On fournit 'content' via un mini fragment.
        "content": (
            f"<p>Une demande de publication en <strong>PROD</strong> a été créée pour le DID "
            f"<code>{did}</code> (version {pr.did_document.version}).</p>"
            f"<p>Demandeur: {getattr(pr.requested_by, 'email', 'inconnu')}.</p>"
            f"<p>ID de demande: <strong>{pr.id}</strong>.</p>"
        ),
    }
    html = _render_with_layout(inner_template=None, context=ctx)
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

    note = (pr.note or "").strip()
    decision_line = "Votre demande de publication a été approuvée." if approved else "Votre demande de publication a été rejetée."
    note_line = f"<p>Note: {note}</p>" if note else ""

    ctx = {
        "title": "Décision de publication",
        "did": did,
        "version": pr.did_document.version,
        "status": pr.status,
        "decided_by": getattr(pr.decided_by, "email", None),
        "content": (
            f"<p>{decision_line}</p>"
            f"<p>DID: <code>{did}</code> (version {pr.did_document.version}).</p>"
            f"{note_line}"
        ),
    }
    html = _render_with_layout(inner_template=None, context=ctx)
    _send_html_email(to=[to_email], subject=subject, html=html)
