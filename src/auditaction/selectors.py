from __future__ import annotations

from datetime import datetime

from django.db.models import QuerySet, Q, Count
from django.utils.dateparse import parse_datetime

from src.auditaction.models import AuditLog


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    # Accept ISO strings; falls back to None on failure
    try:
        dt = parse_datetime(value)
        return dt
    except Exception:
        return None


def audit_actions_queryset(
    *,
    organization_id: str | None,
    category: str | None,
    action: str | None,
    user_id: str | None,
    severity: str | None,
    date_from: str | None,
    date_to: str | None,
    q: str | None,
    base_qs: QuerySet[AuditLog] | None = None,
) -> QuerySet[AuditLog]:
    qs = base_qs or AuditLog.objects.select_related("user", "organization")

    if organization_id:
        qs = qs.filter(organization_id=organization_id)
    if category:
        qs = qs.filter(category=category)
    if action:
        qs = qs.filter(action__icontains=action)
    if user_id:
        qs = qs.filter(user_id=user_id)
    if severity:
        qs = qs.filter(severity=severity)

    df = _parse_dt(date_from)
    dt = _parse_dt(date_to)
    if df:
        qs = qs.filter(created_at__gte=df)
    if dt:
        qs = qs.filter(created_at__lte=dt)

    if q:
        qs = qs.filter(
            Q(action__icontains=q)
            | Q(user__email__icontains=q)
            | Q(target_type__icontains=q)
        )

    return qs.order_by("-created_at")


def audit_actions_list_paginated(
    *,
    organization_id: str | None,
    category: str | None,
    action: str | None,
    user_id: str | None,
    severity: str | None,
    date_from: str | None,
    date_to: str | None,
    q: str | None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[AuditLog]]:
    qs = audit_actions_queryset(
        organization_id=organization_id,
        category=category,
        action=action,
        user_id=user_id,
        severity=severity,
        date_from=date_from,
        date_to=date_to,
        q=q,
    )
    total = qs.count()
    items = list(qs[offset : offset + limit])
    return total, items


def audit_stats_by_category(
    *,
    organization_id: str | None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, any]]:
    qs = audit_actions_queryset(
        organization_id=organization_id,
        category=None,
        action=None,
        user_id=None,
        severity=None,
        date_from=date_from,
        date_to=date_to,
        q=None,
    )
    data = qs.values("category").annotate(count=Count("id")).order_by("-count")
    return list(data)
