# file: src/dids/policies.py
from __future__ import annotations
from typing import Tuple
from django.contrib.auth.models import AbstractBaseUser

from src.users.models import UserRole

def parse_did_segments(did: str) -> Tuple[str, str, str, str]:
    # did:web:{host}:{org}:{user}:{type}
    parts = did.split(":")
    assert len(parts) >= 6 and parts[0] == "did" and parts[1] == "web", "Unsupported DID format"
    host = parts[2]
    org = parts[3]
    user = parts[4]
    doc_type = ":".join(parts[5:])
    return host, org, user, doc_type

def _user_has_role(user: AbstractBaseUser, role: str) -> bool:
    # Superuser natif
    if getattr(user, "is_superuser", False) and role == UserRole.SUPERUSER:
        return True
    # Propriété unique
    if getattr(user, "role", None) == role:
        return True
    # Collection de rôles
    roles = getattr(user, "roles", None)
    if roles and role in roles:
        return True
    # Alias booléens éventuels
    if role == UserRole.ORG_ADMIN and getattr(user, "is_org_admin", False):
        return True
    return False

def is_org_admin(user: AbstractBaseUser, organization) -> bool:
    # SUPERUSER autorisé partout
    if _user_has_role(user, UserRole.SUPERUSER):
        return True
    # Rôle direct
    if _user_has_role(user, UserRole.ORG_ADMIN):
        return True
    # Méthodes/relations d'organisation, si disponibles
    if hasattr(organization, "user_is_admin"):
        try:
            if organization.user_is_admin(user):
                return True
        except Exception:
            pass
    if hasattr(organization, "admin"):
        try:
            return getattr(organization.admin, "id", None) == getattr(user, "id", None)
        except Exception:
            pass
    if hasattr(organization, "admins") and hasattr(organization.admins, "filter"):
        return organization.admins.filter(pk=getattr(user, "pk", 0)).exists()
    return False

def can_publish_prod(user: AbstractBaseUser, organization) -> bool:
    # SUPERUSER et ORG_ADMIN autorisés
    if _user_has_role(user, UserRole.SUPERUSER) or _user_has_role(user, UserRole.ORG_ADMIN):
        return True
    # Droit spécifique booléen
    if getattr(user, "can_publish_prod", False):
        return True
    # Perm Django (si configuré)
    if hasattr(user, "has_perm") and user.has_perm("users.can_publish_prod"):
        return True
    return False
