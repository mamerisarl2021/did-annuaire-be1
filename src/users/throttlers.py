from ninja_extra.throttling import AnonRateThrottle


class PasswordResetRequestThrottle(AnonRateThrottle):
    """
    Rate limit password reset requests per IP.
    This is a first line of defense at the view layer (before any business logic).
    The per-email cache-based limit in the service layer provides a second layer.
    """
    rate = "5/hour"
    scope = "password_reset_request"


class PasswordResetConfirmThrottle(AnonRateThrottle):
    """
    Rate limit password reset confirmations per IP.
    Prevents brute-forcing tokens.
    """
    rate = "10/hour"
    scope = "password_reset_confirm"