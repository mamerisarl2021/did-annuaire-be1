from urllib.parse import urljoin

from django.conf import settings

from src.common.notifications.email import org_admin_emails, render_with_layout, send_html_email
from src.dids.models import PublishRequest

def send_publish_request_notification(pr: PublishRequest) -> None:
    """
    Notify ORG_ADMIN that a publish request to PROD has been created
    """
    org = pr.did.organization
    recipients = org_admin_emails(org)
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
    html = render_with_layout(inner_template="publish_request_content.html", context=ctx)
    send_html_email(to=recipients, subject=subject, html=html)


def send_publish_decision_notification(pr: PublishRequest) -> None:
    """
    Notify of publish request decision
    """
    to_email = getattr(pr.requested_by, "email", None)
    if not to_email:
        return

    did = pr.did.did
    approved = pr.status == PublishRequest.Status.APPROVED
    subject = f"[DID Annuaire] Publication PROD {'approuvée' if approved else 'rejetée'} pour {did}"

    ctx = {
        "title": "Décision de publication",
        "did": did,
        "version": pr.did_document.version,
        "requested_by": getattr(pr.requested_by, "email", "Utilisateur"),
        "status": "APPROVED"
        if pr.status == PublishRequest.Status.APPROVED
        else "REJECTED",
        "note": pr.note.strip() if pr.note else "",
        "dashboard_url": urljoin(settings.FR_APP_DOMAIN, "/dashboard/publish-requests"),
    }
    html = render_with_layout(inner_template="publish_decision_content.html", context=ctx)
    send_html_email(to=[to_email], subject=subject, html=html)
