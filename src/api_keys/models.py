import secrets
import hashlib

from django.db import models
from src.common.models import BaseModel


class APIKey(BaseModel):
    """Clés API pour accès programmatique à l'annuaire"""

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="api_keys"
    )
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_api_keys",
    )
    name = models.CharField(max_length=255)
    key_prefix = models.CharField(max_length=12, unique=True, db_index=True)
    key_hash = models.CharField(max_length=255, unique=True)

    permissions = models.JSONField(
        default=list, help_text="['did:read', 'did:resolve']"
    )
    rate_limit_per_hour = models.IntegerField(default=1000)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        constraints = [
            models.UniqueConstraint(
                fields=["key_prefix"], name="api_key_prefix_unique"
            ),
            models.UniqueConstraint(fields=["key_hash"], name="api_key_hash_unique"),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"

    @staticmethod
    def generate_key():
        """Génère une nouvelle clé API"""
        return f"didann_{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_key(plain_key: str) -> str:
        """Hash une clé pour stockage sécurisé"""
        return hashlib.sha256(plain_key.encode()).hexdigest()
