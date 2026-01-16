from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from src.auditaction.services import audit_action_create
from src.auditaction.models import AuditCategory, AuditAction


@receiver(user_logged_in)
def _on_login(sender, request, user, **kwargs):
    audit_action_create(user=user,
                        action=AuditAction.AUTH_LOGIN_SUCCESS,
                        category=AuditCategory.AUTH,
                        details={"path": request.path},
                        request=request,
                        )


@receiver(user_logged_out)
def _on_logout(sender, request, user, **kwargs):
    audit_action_create(user=user,
                        action=AuditAction.AUTH_LOGOUT,
                        category=AuditCategory.AUTH,
                        details={"path": request.path},
                        request=request,
                        )


@receiver(user_login_failed)
def _on_login_failed(sender, credentials, request, **kwargs):
    email = credentials.get("username") or credentials.get("email")
    audit_action_create(user=None,
                        action=AuditAction.AUTH_LOGIN_FAILED,
                        category=AuditCategory.AUTH,
                        details={"email": email, "path": getattr(request, "path", "")},
                        request=request,
                        )
