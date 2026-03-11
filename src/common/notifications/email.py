from typing import Iterable, Any
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from src.emails.services import email_send
from src.users.models import User, UserRole

DEFAULT_LAYOUT = "email_default_layout.html"

def render_with_layout(inner_template: str | None, context: dict[str, Any]) -> str:
    """
    Envelope email in the layout by default. If 'inner_template' is provided,
    render it first then inject it into the layout via {{ content|safe }}.
    """
    if inner_template:
        content_html = render_to_string(inner_template, context)
        outer_ctx = dict(context)
        outer_ctx["content"] = content_html
        return render_to_string(DEFAULT_LAYOUT, outer_ctx)

    # No inner template: expect content to be in the context
    return render_to_string(DEFAULT_LAYOUT, context)

def send_html_email(
    to: Iterable[str],
    subject: str,
    html: str,
    text_fallback: str | None = None,
    cc: Iterable[str] | None = None,
    bcc: Iterable[str] | None = None,
) -> None:
    text = text_fallback or strip_tags(html)

    email_send(
        to=list(to),
        subject=subject,
        html=html,
        text=text,
        cc=list(cc) if cc else None,
        bcc=list(bcc) if bcc else None,
    )

def org_admin_emails(org) -> list[str]:
    """
    Return emails of ORG_ADMINs in the organization.
    """
    qs = (
        User.objects.filter(organization=org, is_active=True)
        .filter(role__contains=[UserRole.ORG_ADMIN])
        .exclude(email__isnull=True)
        .exclude(email="")
        .values_list("email", flat=True)
        .distinct()
    )
    return list(qs)


