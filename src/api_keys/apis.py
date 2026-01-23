from ninja_extra import api_controller, route, ControllerBase
from ninja_jwt.authentication import JWTAuth
from django.shortcuts import get_object_or_404

from src.api_keys.models import APIKey
from src.api_keys import services, selectors
from src.users.models import UserRole


@api_controller("/api-keys", tags=["API Keys"], auth=JWTAuth())
class APIKeyController(ControllerBase):
    @route.post("/")
    def create_api_key(self, name: str, permissions: list[str], expires_at: str = None):
        """
        Créer une clé API

        IMPORTANT: La clé en clair n'est retournée qu'UNE SEULE FOIS
        """

        user = self.context.request.auth

        if user.role not in [UserRole.ORG_ADMIN, UserRole.SUPERUSER]:
            return self.create_response(
                message="Only ORG_ADMIN can create API keys", extra={}, status_code=403
            )

        api_key, plain_key = services.api_key_create(
            organization=user.organization,
            created_by=user,
            name=name,
            permissions=permissions,
            expires_at=expires_at,
        )

        return {
            "id": api_key.id,
            "name": api_key.name,
            "key_prefix": api_key.key_prefix,
            "plain_key": plain_key,  # ⚠️ Affiché UNE SEULE FOIS!
            "permissions": api_key.permissions,
            "expires_at": api_key.expires_at.isoformat()
            if api_key.expires_at
            else None,
            "created_at": api_key.created_at.isoformat(),
        }

    @route.get("/")
    def list_api_keys(self):
        """Lister les clés API de mon organisation"""

        user = self.context.request.auth

        keys = selectors.api_key_list_by_organization(organization=user.organization)

        return [
            {
                "id": key.id,
                "name": key.name,
                "key_prefix": key.key_prefix,
                "is_active": key.is_active,
                "permissions": key.permissions,
                "last_used_at": key.last_used_at.isoformat()
                if key.last_used_at
                else None,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "created_at": key.created_at.isoformat(),
            }
            for key in keys
        ]

    @route.post("/{api_key_id}/revoke")
    def revoke_api_key(self, api_key_id: str):
        """Révoquer une clé API"""

        user = self.context.request.auth

        if user.role not in [UserRole.ORG_ADMIN, UserRole.SUPERUSER]:
            return self.create_response(
                message="Only ORG_ADMIN can revoke API keys", extra={}, status_code=403
            )

        key = get_object_or_404(APIKey, id=api_key_id, organization=user.organization)

        services.api_key_revoke(api_key_id=key.id, revoked_by=user)

        return self.create_response(
            message="API key revoked successfully", extra={}, status_code=200
        )


# @route.post('/')
# def create_api_key(self, name: str, permissions: list, expires_at: str | None = None):
#    user = self.context.request.auth
#    ensure_role_in(user, UserRole.ORG_ADMIN, UserRole.SUPERUSER)
#    key, plain = services.api_key_create(organization=user.organization, created_by=user, name=name, permissions=permissions, expires_at=expires_at)
#    return self.create_response(message="API key created", data=api_key_created_dto(key, plain), status_code=201)

# @route.get('/')
# def list_api_keys(self):
#    user = self.context.request.auth
#    keys = selectors.api_key_list_by_organization(organization=user.organization)
#    return self.create_response(message="API keys", data=[api_key_to_list_dto(k) for k in keys], status_code=200)
