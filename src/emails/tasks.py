from celery import shared_task
from typing import Any
from src.emails.services import email_send


@shared_task(name="emails.send_email")
def send_email_task(payload: dict[str, Any]) -> bool:
    """
    payload example:
      {
        "to": ["user@example.com"],
        "subject": "Hello",
        "html": "<p>Hi</p>",
        "text": "Hi",
        "cc": [], "bcc": [], "reply_to": [],
        "attachments": [["file.txt", "base64_or_bytes", "text/plain"]],
        "extra_headers": {},
      }
    """
    # Coerce attachments content to bytes if needed (left to caller if using base64)
    return email_send(**payload)
