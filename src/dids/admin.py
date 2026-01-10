from django.contrib import admin
from src.dids.models import Application, DIDDocument, PublicKey


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "slug",
        "organization",
        "created_by",
        "is_active",
        "created_at",
    ]
    list_filter = ["is_active", "organization"]
    search_fields = ["name", "slug", "organization__name"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(DIDDocument)
class DIDDocumentAdmin(admin.ModelAdmin):
    list_display = ["did", "status", "application", "version", "created_at"]
    list_filter = ["status", "application__organization"]
    search_fields = ["did", "domain"]
    readonly_fields = ["created_at", "updated_at", "document"]

    fieldsets = (
        (
            "Basic Info",
            {
                "fields": (
                    "did",
                    "application",
                    "created_by",
                    "domain",
                    "version",
                    "status",
                )
            },
        ),
        ("Document", {"fields": ("document",), "classes": ("collapse",)}),
        (
            "Workflow",
            {
                "fields": (
                    "preprod_published_at",
                    "preprod_published_by",
                    "validated_at",
                    "validated_by",
                    "prod_published_at",
                    "prod_published_by",
                    "revoked_at",
                    "revoked_by",
                    "revocation_reason",
                )
            },
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ["key_id", "did_document", "key_type", "is_active", "created_at"]
    list_filter = ["key_type", "is_active"]
    search_fields = ["key_id", "did_document__did"]
    readonly_fields = ["created_at", "updated_at"]
