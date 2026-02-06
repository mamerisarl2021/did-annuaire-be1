from ninja_extra import api_controller, route
from ninja import File, UploadedFile, Form
from django.shortcuts import get_object_or_404

from .schemas import OrgCreatePayload
from src.common.utils import validate_uuid
from src.core.apis import BaseAPIController
from src.organizations.models import Organization
from src.organizations import services
from src.users.models import UserRole


@api_controller("/organizations", tags=["Organizations"])
class OrganizationController(BaseAPIController):
    @route.post("/", auth=None)
    def create_organization(
        self,
        data: OrgCreatePayload = Form(...),
        authorization_document: UploadedFile = File(...),
        justification_document: UploadedFile | None = File(None),
    ):
        org = services.organization_create(
            name=data.name,
            org_type=data.org_type,
            country=data.country,
            email=data.email,
            phone=data.phone,
            address=data.address,
            allowed_email_domains=data.allowed_email_domains,
            admin_email=data.admin_email,
            admin_first_name=data.admin_first_name,
            admin_last_name=data.admin_last_name,
            admin_phone=data.admin_phone,
            functions=data.functions,
            authorization_document=authorization_document,
            justification_document=justification_document,
        )

        admin = org.users.filter(role=UserRole.ORG_ADMIN).order_by("created_at").first()
        return self.create_response(
            message="Organization created successfully",
            data={
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "status": org.status,
                "admin": {"id": admin.id, "email": admin.email} if admin else None,
            },
            status_code=201,
        )

    # @route.get("/", auth=JWTAuth())
    # def list_organizations(self, filters: Query[AdminOrgFilterParams]):
    #     user = self.context.request.auth
    #     ensure_role_in(user, UserRole.ORG_ADMIN)

    #     qs = selectors.organization_list_by_admins(
    #         status=filters.status,
    #         user=user
    #     )

    #     paginator = Paginator(default_page_size=10, max_page_size=100)
    #     page_items, meta = paginator.paginate_queryset(qs, self.context.request)

    #     data = [org_to_list_dto_admin_org(o) for o in page_items]

    #     # Message dynamique
    #     message = "Organizations"
    #     if filters.status:
    #         message += f" (status={filters.status})"

    #     return self.create_response(
    #         message=message,
    #         data={"items": data, "pagination": meta},
    #         status_code=200,
    #     )

    # @route.get("/id/{org_id}", auth=JWTAuth())
    # def get_organization(self, org_id: str):
    #     user = self.context.request.auth
    #     org_id = validate_uuid(org_id)
    #     org = get_object_or_404(Organization, id=org_id)
    #     ensure_role_in(user, UserRole.ORG_ADMIN)
    #     data = org_to_detail_dto_admin_org(org)
    #     return self.create_response(
    #         message="Organization details", data=data, status_code=200
    #     )

    # @route.get("/stats", auth=JWTAuth())
    # def get_organizations_stats(self):
    #     """
    #     Organization stats per admin's org
    #     """
    #     user = self.context.request.auth
    #     ensure_role_in(user, UserRole.ORG_ADMIN)

    #     stats = selectors.organization_stats_for_admin(user=user)

    #     return self.create_response(
    #         message="Organization statistics",
    #         data=stats,
    #         status_code=200,
    #     )

    @route.get("/id/{org_id}/status", auth=None)
    def get_organization_status(self, org_id: str):
        """
        Endpoint public pour récupérer le statut d'une organisation
        Pas d'authentification requise
        """
        org_id = validate_uuid(org_id)
        org = get_object_or_404(Organization, id=org_id)

        return self.create_response(
            message="Organization status", data={"status": org.status}, status_code=200
        )
