from ninja import Query
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth
from django.shortcuts import get_object_or_404

from src.core.apis import BaseAPIController
from src.core.policies import ensure_superuser
from src.api.pagination import Paginator
from src.common.utils import validate_uuid

from src.organizations.models import Organization
from src.organizations import selectors as org_selectors
from src.organizations.schemas import OrgFilterParams
from src.superadmin.presenters import (
    org_to_list_dto_superadmin,
    org_to_detail_dto_superadmin,
    user_to_list_dto_superadmin,
)
from src.superadmin import services as sa_services
from src.superadmin.schemas import RefusePayload
from src.users import selectors as user_selectors
from src.users.schemas import UserFilterParams


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

        qs = org_selectors.organization_list_with_admins(
            status=filters.status, search=filters.search
        )

        paginator = Paginator(default_page_size=20, max_page_size=100)
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
        org = org_selectors.organization_get_with_admin(org_id=org_uuid)
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
        sa_services.org_validate(organization_id=org_uuid, validated_by=user)
        return self.create_response(
            message="Organization validated successfully", status_code=200
        )

    @route.post("/organizations/{org_id}/refuse")
    def refuse(self, org_id: str, payload: RefusePayload):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        sa_services.org_refuse(
            organization_id=org_uuid, refused_by=user, reason=payload.reason
        )
        return self.create_response(message="Organization refused", status_code=200)

    @route.patch("/organizations/{org_id}/toggle-activation")
    def toggle_activation(self, org_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        org_uuid = validate_uuid(org_id)
        org = sa_services.org_toggle_activation(
            organization_id=org_uuid, toggled_by=user
        )
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
        sa_services.org_delete(organization_id=org_uuid, deleted_by=user)
        return self.create_response(message="Organization deleted", status_code=200)

    @route.get("/organizations/users")
    def list_all_users(self, filters: Query[UserFilterParams]):
        """
        Liste TOUS les utilisateurs (toutes organisations)
        Requiert: SUPERUSER
        Supporte: status, role, search + pagination
        """
        current_user = self.context.request.auth
        ensure_superuser(current_user)

        qs = user_selectors.user_list(
            status=filters.status, role=filters.role, search=filters.search
        )

        paginator = Paginator(default_page_size=10, max_page_size=100)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [user_to_list_dto_superadmin(u) for u in items]
        return self.create_response(
            message="All users fetched",
            data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
            status_code=200,
        )

    @route.get("/organizations/{org_id}/users")
    def list_organization_users(self, org_id: str, filters: Query[UserFilterParams]):
        """
        Liste les utilisateurs d'UNE organisation spécifique
        Requiert: SUPERUSER
        Supporte: status, role, search + pagination
        """
        current_user = self.context.request.auth
        ensure_superuser(current_user)

        org_uuid = validate_uuid(org_id)
        organization = get_object_or_404(Organization, id=org_uuid)

        qs = user_selectors.user_list(
            organization=organization,
            status=filters.status,
            role=filters.role,
            search=filters.search,
        )

        paginator = Paginator(default_page_size=10, max_page_size=100)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [user_to_list_dto_superadmin(u) for u in items]
        return self.create_response(
            message=f"Users from {organization.name} fetched",
            data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
            status_code=200,
        )

    @route.post("/users/{user_id}/resend-invite")
    def resend_invite(self, user_id: str):
        user = self.context.request.auth
        ensure_superuser(user)
        sa_services.user_resend_invite(
            user_id=validate_uuid(user_id), requested_by=user
        )
        return self.create_response(message="Invitation re-sent", status_code=200)

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
