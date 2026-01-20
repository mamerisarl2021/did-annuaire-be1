from django.contrib import admin
from src.api_keys.models import APIKey


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "key_prefix",
        "organization",
        "is_active",
        "created_at",
        "last_used_at",
    ]
    list_filter = ["is_active", "organization"]
    search_fields = ["name", "key_prefix", "organization__name"]
    readonly_fields = [
        "key_prefix",
        "key_hash",
        "created_at",
        "updated_at",
        "last_used_at",
    ]

    fieldsets = (
        ("Basic Info", {"fields": ("organization", "created_by", "name")}),
        (
            "Key Details",
            {
                "fields": (
                    "key_prefix",
                    "key_hash",
                    "permissions",
                    "rate_limit_per_hour",
                )
            },
        ),
        ("Status", {"fields": ("is_active", "expires_at", "last_used_at")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )
