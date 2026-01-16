from datetime import timedelta
from django.utils import timezone
from src.core.exceptions import DomainValidationError


def enforce_min_interval(last_sent_at, *, seconds: int, code: str, message: str, ) -> None:
    """
    Raise a DomainValidationError if now - last_sent_at < seconds.
    Use this for lightweight rate limits (no DB changes).
    """
    if last_sent_at and (timezone.now() - last_sent_at) < timedelta(seconds=seconds):
        raise DomainValidationError(message=message, code=code)
