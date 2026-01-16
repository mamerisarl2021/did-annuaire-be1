from django.db import transaction
from django.utils import timezone
from src.api_keys.models import APIKey
from src.auditaction.models import AuditAction
from src.auditaction.services import audit_action_create


@transaction.atomic
def api_key_create(*, organization, created_by, name: str, permissions: list, expires_at=None) -> tuple:
    """
    Créer une clé API

    Retourne (api_key, plain_key)
    IMPORTANT: La clé en clair n'est retournée qu'UNE SEULE FOIS
    """

    plain_key = APIKey.generate_key()
    key_hash = APIKey.hash_key(plain_key)
    key_prefix = plain_key[:12]

    api_key = APIKey.objects.create(organization=organization,
                                    created_by=created_by,
                                    name=name,
                                    key_prefix=key_prefix,
                                    key_hash=key_hash,
                                    permissions=permissions,
                                    expires_at=expires_at,
                                    is_active=True)

    # Audit
    audit_action_create(user=created_by,
                        action=AuditAction.API_KEY_CREATED,
                        details={'api_key_id': api_key.id,
                                 'name': name,
                                 'permissions': permissions}
                        )

    return api_key, plain_key


@transaction.atomic
def api_key_revoke(*, api_key_id: int, revoked_by) -> APIKey:
    """Révoquer une clé API"""

    api_key = APIKey.objects.get(id=api_key_id)
    api_key.is_active = False
    api_key.save()

    # Audit
    audit_action_create(user=revoked_by,
                        action=AuditAction.API_KEY_REVOKED,
                        details={'api_key_id': api_key.id,
                                 'name': api_key.name}
                        )

    return api_key


def api_key_validate(*, plain_key: str):
    """
    Valider une clé API

    Retourne l'APIKey si valide, None sinon
    """

    key_hash = APIKey.hash_key(plain_key)

    try:
        api_key = APIKey.objects.select_related('organization').get(key_hash=key_hash, is_active=True)

        # Vérifier expiration
        if api_key.expires_at and api_key.expires_at < timezone.now():
            return None

        # Mettre à jour last_used_at
        api_key.last_used_at = timezone.now()
        api_key.save(update_fields=['last_used_at'])

        return api_key
    except APIKey.DoesNotExist:
        return None
