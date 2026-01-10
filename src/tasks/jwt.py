from celery import shared_task
from django.core.management import call_command


@shared_task(name="jwt.flush_expired_tokens")
def flush_expired_tokens() -> None:
    # Requires 'ninja_jwt.token_blacklist' in INSTALLED_APPS
    call_command("flushexpiredtokens")
