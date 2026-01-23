from ninja_extra import api_controller, route, ControllerBase
from ninja_jwt.authentication import JWTAuth
from django.shortcuts import get_object_or_404

from src.auditaction.models import AuditAction
from src.auditaction import selectors
from src.users.models import UserRole


def _scope_org_id_for_user(user) -> str | None:
    # SUPERUSER sees all orgs, others are scoped to own org
    if getattr(user, "role", "").upper() == UserRole.SUPERUSER:
        return None
    return getattr(user, "organization_id", None)


@api_controller("/audit", tags=["Audit"], auth=JWTAuth())
class AuditActionController(ControllerBase):
    @route.get("/actions")
    def list_actions(
        self,
        category=None,
        action=None,
        user_id=None,
        severity=None,
        date_from=None,
        date_to=None,
        q=None,
        limit=50,
        offset=0,
        organization_id=None,
    ):
        """
        List audit actions with filtering and simple pagination.
        SUPERUSER can pass organization_id explicitly; others are auto-scoped.
        """
        current = self.context.request.auth
        scoped_org = (
            organization_id
            if getattr(current, "role", "").upper() == "SUPERUSER"
            else _scope_org_id_for_user(current)
        )

        total, items = selectors.audit_actions_list_paginated(
            organization_id=scoped_org,
            category=category,
            action=action,
            user_id=user_id,
            severity=severity,
            date_from=date_from,
            date_to=date_to,
            q=q,
            limit=min(max(1, limit), 200),
            offset=max(0, offset),
        )

        return {
            "count": total,
            "items": [
                {
                    "id": obj.id,
                    "timestamp": obj.created_at.isoformat(),
                    "category": obj.category,
                    "action": obj.action,
                    "severity": obj.severity,
                    "user": obj.user.email if obj.user else None,
                    "organization": obj.organization.slug if obj.organization else None,
                    "target_type": obj.target_type,
                    "target_id": obj.target_id,
                    "ip": obj.ip_address,
                }
                for obj in items
            ],
        }

    @route.get("/actions/{audit_id}")
    def get_action(self, audit_id: str):
        current = self.context.request.auth
        obj = get_object_or_404(AuditAction, id=audit_id)

        # Scope check for non-superusers
        if getattr(current, "role", "").upper() != "SUPERUSER":
            if not obj.organization_id or obj.organization_id != getattr(
                current, "organization_id", None
            ):
                return self.create_response({"detail": "Permission denied"}, status=403)

        return {
            "id": obj.id,
            "timestamp": obj.created_at.isoformat(),
            "category": obj.category,
            "action": obj.action,
            "severity": obj.severity,
            "user": obj.user.email if obj.user else None,
            "organization": obj.organization.slug if obj.organization else None,
            "target_type": obj.target_type,
            "target_id": obj.target_id,
            "details": obj.details,
            "ip": obj.ip_address,
            "user_agent": obj.user_agent,
            "request_id": obj.request_id,
        }

    @route.get("/stats/by-category")
    def stats_by_category(
        self,
        date_from=None,
        date_to=None,
        organization_id=None,
    ):
        current = self.context.request.auth
        scoped_org = (
            organization_id
            if getattr(current, "role", "").upper() == "SUPERUSER"
            else _scope_org_id_for_user(current)
        )
        data = selectors.audit_stats_by_category(
            organization_id=scoped_org, date_from=date_from, date_to=date_to
        )
        return {"items": data}
