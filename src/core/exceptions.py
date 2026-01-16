from __future__ import annotations
from typing import Any


class ApplicationError(Exception):
    def __init__(self, message, extra=None):
        super().__init__(message)
        self.message = message
        self.extra = extra or {}

class ValidationError(ApplicationError):
    """Erreur de validation métier"""
    pass


class PermissionDeniedError(ApplicationError):
    """Erreur de permission"""
    pass


class NotFoundError(ApplicationError):
    """Ressource non trouvée"""
    pass


class AuthenticationError(ApplicationError):
    """Erreur d'authentification"""
    pass

class APIError(Exception):
    def __init__(self, *, message: str, code: str, status: int, errors: Any = None, extra: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.errors = errors
        self.extra = extra or {}


class DomainConflictError(APIError):
    def __init__(self, *, message: str, code: str, errors: Any = None, extra: dict[str, Any] | None = None):
        super().__init__(message=message, code=code, status=409, errors=errors, extra=extra)


class DomainValidationError(APIError):
    def __init__(self, *, message: str, code: str = "VALIDATION_ERROR", errors: Any = None, extra: dict[str, Any] | None = None):
        super().__init__(message=message, code=code, status=422, errors=errors, extra=extra)
