
from django.contrib import admin
from src.auditaction.models import AuditLog


@admin.register(AuditLog)
class AuditActionAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "category",
        "action",
        "severity",
        "user",
        "organization",
        "target_type",
        "target_id",
        "ip_address",
    )
    list_filter = ("category", "severity", "organization")
    search_fields = ("action", "organization__users__email", "organization__name", "target_type")
    readonly_fields = (
        "created_at",
        "updated_at",
        "user",
        "organization",
        "category",
        "action",
        "severity",
        "target_type",
        "target_id",
        "details",
        "ip_address",
        "user_agent",
        "request_id",
    )
    ordering = ("-created_at",)