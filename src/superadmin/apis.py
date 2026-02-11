from django.http import JsonResponse
from ninja import Query, Body
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth
from django.conf import settings

from src.core.apis import BaseAPIController
from src.core.policies import ensure_superuser
from src.api.pagination import Paginator
from src.common.utils import validate_uuid
from src.dids.publishing.selectors import relpaths_for_did
from src.dids.publishing.services import remove_published_path
from src.dids.resolver.services import parse_did_web
from src.organizations.models import Organization
from src.superadmin import selectors as sa_selectors
from .schemas import OrgFilterParams, OrgRefusePayload
from src.superadmin.presenters import (
    org_to_list_dto_superadmin,
    org_to_detail_dto_superadmin,
)
from . import services
from . import selectors
# from src.users import selectors as user_selectors
# from src.users.schemas import FilterParams


@api_controller("/superadmin", tags=["Super Admin"], auth=JWTAuth())
class SuperAdminController(BaseAPIController):
    
    @route.get("/organizations")
    def list_organizations(self, filters: Query[OrgFilterParams]):  # ← MODIFIÉ
        """
        Liste les organisations pour SuperAdmin
        Supporte: status, search (name/slug) + pagination
        """
        user = self.context.request.auth
        ensure_superuser(user)

        qs = sa_selectors.organization_list_with_admins(
            status=filters.status, search=filters.search
        )

        paginator = Paginator(default_page_size=10, max_page_size=20)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [org_to_list_dto_superadmin(o) for o in items]

        # Message dynamique
        msg_parts = []
        if filters.status:
            msg_parts.append(f"status={filters.status}")
        if filters.search:
            msg_parts.append(f"search='{filters.search}'")

        message = "Organizations"
        if msg_parts:
            message += f" ({', '.join(msg_parts)})"

        return self.create_response(
            message=message, data={"items": data, "pagination": meta}, status_code=200
        )

    @route.get("/organizations/{org_id}")
    def get_organization(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        org = selectors.organization_get_with_admin(org_id=org_uuid)
        return self.create_response(
            message="Organization details",
            data=org_to_detail_dto_superadmin(org),
            status_code=200,
        )

    @route.post("/organizations/{org_id}/validate")
    def validate(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_validate(organization_id=org_uuid, validated_by=user)
        return self.create_response(
            message="Organization validated successfully", status_code=200
        )

    @route.post("/organizations/{org_id}/refuse")
    def refuse(self, org_id: str, payload: OrgRefusePayload):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_refuse(organization_id=org_uuid, refused_by=user, reason=payload.reason)
        return self.create_response(message="Organization refused", status_code=200)

    @route.patch("/organizations/{org_id}/toggle-activation")
    def toggle_activation(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        org = services.organization_toggle_activation(organization_id=org_uuid, toggled_by=user)
        return self.create_response(
            message="Organization status updated",
            data={"id": org.id, "status": org.status},
            status_code=200,
        )

    @route.delete("/organizations/{org_id}")
    def delete_org(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        services.organization_delete(organization_id=org_uuid, deleted_by=user)
        return self.create_response(message="Organization deleted", status_code=200)

    # @route.get("/organizations/users")
    # def list_users(self, filters: Query[UserFilterParams]):
    #     """
    #     Liste TOUS les utilisateurs (toutes organisations)
    #     Requiert: SUPERUSER
    #     Supporte: status, role, search + pagination
    #     """
    #     current_user = self.context.request.auth
    #     ensure_superuser(current_user)

    #     qs = user_selectors.user_list(
    #         status=filters.status, role=filters.role, search=filters.search
    #     )

    #     paginator = Paginator(default_page_size=10, max_page_size=100)
    #     items, meta = paginator.paginate_queryset(qs, self.context.request)

    #     data = [user_to_list_dto_superadmin(u) for u in items]
    #     return self.create_response(
    #         message="All users fetched",
    #         data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
    #         status_code=200,
    #     )

    # @route.get("/organizations/{org_id}/users")
    # def list_organization_users(self, org_id: str, filters: Query[UserFilterParams]):
    #     """
    #     Liste les utilisateurs d'UNE organisation spécifique
    #     Requiert: SUPERUSER
    #     Supporte: status, role, search + pagination
    #     """
    #     current_user = self.context.request.auth
    #     ensure_superuser(current_user)

    #     org_uuid = validate_uuid(org_id)
    #     organization = get_object_or_404(Organization, id=org_uuid)

    #     qs = user_selectors.user_list(
    #         organization=organization,
    #         status=filters.status,
    #         role=filters.role,
    #         search=filters.search,
    #     )

    #     paginator = Paginator(default_page_size=10, max_page_size=100)
    #     items, meta = paginator.paginate_queryset(qs, self.context.request)

    #     data = [user_to_list_dto_superadmin(u) for u in items]
    #     return self.create_response(
    #         message=f"Users from {organization.name} fetched",
    #         data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
    #         status_code=200,
    #     )



    @route.get("/dids")
    def list_dids(
            self,
            request,
            page: int = 1,
            page_size: int = 20,
            q: str | None = None,
            organization_id: str | None = None,
            status: str | None = None,  # DRAFT | ACTIVE | DEACTIVATED
    ):
        user = self.context.request.auth
        ensure_superuser(user)

        qs = selectors.did_list_all_with_context(
            q=q,
            organization_id=organization_id,
            status=status,
        )

        paginator = Paginator(default_page_size=20, max_page_size=100)
        rows, meta = paginator.paginate_queryset(qs, request)

        items = []
        for d in rows:
            items.append(
                {
                    "did": d.did,
                    "organization": str(getattr(d.organization, "slug", "")),
                    "owner": str(getattr(d.owner, "name", "")),
                    "document_type": d.document_type,
                    "status": d.status,
                    "latest_version": d.latest_version or 0,
                    "created_at": d.created_at.isoformat() if getattr(d, "created_at", None) else None,
                }
            )

        return JsonResponse({"items": items, "pagination": meta}, status=200, content_type="application/json")

    @route.get("/users")
    def list_users(
            self,
            request,
            page: int = 1,
            page_size: int = 20,
            q: str | None = None,
            organization_id: str | None = None,
            role: str | None = None,
            is_active: bool | None = None,
            status: str | None = None,
    ):
        # Superuser-only
        user = self.context.request.auth
        ensure_superuser(user)

        qs = selectors.users_list_all(
            q=q,
            organization_id=organization_id,
            role=role,
            is_active=is_active,
            status=status,
        )

        paginator = Paginator(default_page_size=20, max_page_size=100)
        rows, meta = paginator.paginate_queryset(qs, request)

        items = []
        for u in rows:
            items.append(
                {
                    "id": str(getattr(u, "id", "")),
                    "email": getattr(u, "email", None),
                    "first_name": getattr(u, "first_name", None),
                    "last_name": getattr(u, "last_name", None),
                    "phone": getattr(u, "phone", None),
                    "organization_id": str(getattr(u.organization, "id", "")) if getattr(u, "organization",
                                                                                         None) else None,
                    "organization_name": getattr(u.organization, "name", None) if getattr(u, "organization",
                                                                                          None) else None,
                    "roles": list(getattr(u, "role", []) or []),
                    "status": getattr(u, "status", None),
                    "is_active": bool(getattr(u, "is_active", False)),
                    "is_org_admin": bool(getattr(u, "is_org_admin", False)),
                    "created_at": u.created_at.isoformat() if getattr(u, "created_at", None) else None,
                    "last_login": u.last_login.isoformat() if getattr(u, "last_login", None) else None,
                }
            )

        return JsonResponse({"items": items, "pagination": meta}, status=200, content_type="application/json")

    @route.get("/organizations/stats")
    def get_organizations_stats(self):
        """
        Statistiques des organisations par statut
        Requiert: SUPERUSER
        """
        user = self.context.request.auth
        ensure_superuser(user)

        from src.organizations.models import OrganizationStatus

        stats = {
            "all": Organization.objects.count(),
            "pending": Organization.objects.filter(
                status=OrganizationStatus.PENDING
            ).count(),
            "active": Organization.objects.filter(
                status=OrganizationStatus.ACTIVE
            ).count(),
            "suspended": Organization.objects.filter(
                status=OrganizationStatus.SUSPENDED
            ).count(),
            "refused": Organization.objects.filter(
                status=OrganizationStatus.REFUSED
            ).count(),
        }

        return self.create_response(
            message="Organizations statistics", data=stats, status_code=200
        )

    @route.post("/cleanup")
    def cleanup_published_folder(self, request, body: dict = Body(...)):
        """
        Superuser-only. Remove a published path under DIDS_ROOT.
        Body:
        { "did": "<did:web:...>",
            "scope": "doc_type" | "user" | "org",   # default "doc_type"
            "prune_empty_parents": false            # applies when scope != "org"
        }
        Validates host and path containment; nginx remains RO; deletion is done by backend RW mount.
        """
        if not getattr(self.context.request.auth, "is_superuser", False):
            raise HttpError(403, "Forbidden")

        did = (body or {}).get("did")
        if not did or not isinstance(did, str):
            raise HttpError(400, "did is required")

        scope = (body or {}).get("scope", "doc_type")
        if scope not in {"doc_type", "user", "org"}:
            raise HttpError(400, "Invalid scope: expected 'doc_type', 'user', or 'org'")

        # Safety: host must match configured host
        host, org, user, doc_type = parse_did_web(did)
        expected = getattr(
            settings, "DID_DOMAIN_HOST", "annuairedid-be.qcdigitalhub.com"
        )
        if host != expected:
            raise HttpError(400, f"Host mismatch: expected {expected}, got {host}")

        # Compute rel path for scope
        paths = relpaths_for_did(did)
        rel_map = {
            "doc_type": paths["doc_type"],
            "user": paths["user"],
            "org": paths["org"],
        }
        rel_path = rel_map[scope]

        # Delete; prune parents only when not removing the org-level directly
        prune = bool((body or {}).get("prune_empty_parents")) and scope != "org"
        try:
            result = remove_published_path(rel_path, prune_empty_parents=prune)
        except ValueError as ve:
            raise HttpError(400, str(ve))

        message = "Removed" if result["removed"] else "Not found"
        return self.create_response(
            message=message,
            data={
                "did": did,
                "scope": scope,
                "org": org,
                "user": user,
                "document_type": doc_type,
                "rel_path": rel_path,
                "abs_path": result["abs_path"],
                "removed": result["removed"],
                "pruned": result.get("pruned", []),
            },
            status_code=200,
        )

    @route.get("/health", auth=None)
    def health_stats(self):
        from orbit import get_watcher_status, get_failed_watchers

        # Get status of all watchers
        status = get_watcher_status()
        # {'cache': {'installed': True, 'error': None, 'disabled': False}, ...}

        # Get only failed watchers
        failed = get_failed_watchers()
        # {'celery': 'ModuleNotFoundError: No module named celery'}

        return self.create_response(
            data={"orbit_watcher_status": status, "orbit_failed_watchers": failed}
        )

