from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth
from ninja import File, UploadedFile, Form, Query
from django.shortcuts import get_object_or_404

from src.core.policies import ensure_role_in, ensure_superuser
from src.organizations.schemas import OrgCreatePayload, OrgFilterParams
from src.common.utils import validate_uuid
from src.core.apis import BaseAPIController
from src.organizations.models import Organization
from src.organizations import services, selectors
from src.users.models import UserRole
from src.api.pagination import Paginator
from src.organizations.presenters import org_to_detail_dto_admin, org_to_list_dto_admin


@api_controller('/organizations', tags=['Organizations'])
class OrganizationController(BaseAPIController):

    @route.post('/', auth=None)
    def create_organization(self, data: OrgCreatePayload = Form(...), authorization_document: UploadedFile = File(...),
                            justification_document: UploadedFile | None = File(None), ):
        org = services.organization_create(name=data.name, org_type=data.org_type, country=data.country,
                                           email=data.email, phone=data.phone, address=data.address,
                                           allowed_email_domains=data.allowed_email_domains,
                                           admin_email=data.admin_email, admin_first_name=data.admin_first_name,
                                           admin_last_name=data.admin_last_name, admin_phone=data.admin_phone,
                                           functions=data.functions, authorization_document=authorization_document,
                                           justification_document=justification_document,)

        admin = org.users.filter(role=UserRole.ORG_ADMIN).order_by("created_at").first()
        return self.create_response(
            message="Organization created successfully",
            data={
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "status": org.status,
                "admin": {"id": admin.id, "email": admin.email} if admin else None
            },
            status_code=201,
        )

    @route.get('/', auth=JWTAuth())
    def list_organizations(self, filters: Query[OrgFilterParams]):  # ← MODIFIÉ
        """
        Liste les organisations
        Supporte: status, search (name/slug) + pagination
        """
        user = self.context.request.auth
        ensure_role_in(user, UserRole.ORG_ADMIN)

        qs = selectors.organization_list_with_admins(
            status=filters.status,
            search=filters.search
        )

        paginator = Paginator(default_page_size=10, max_page_size=100)
        page_items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [org_to_list_dto_admin(o) for o in page_items]

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
            message=message,
            data={"items": data, "pagination": meta},
            status_code=200,
        )

    @route.get('/id/{org_id}', auth=JWTAuth())
    def get_organization(self, org_id: str):
        user = self.context.request.auth
        org_id = validate_uuid(org_id)
        org = get_object_or_404(Organization, id=org_id)
        ensure_role_in(user, UserRole.ORG_ADMIN)
        data = org_to_detail_dto_admin(org)
        return self.create_response(message="Organization details", data=data, status_code=200)

    @route.get("/stats", auth=JWTAuth())
    def get_organizations_stats(self):
        """
        Statistiques des organisations par statut
        Requiert: ORG_ADMIN
        """
        user = self.context.request.auth
        ensure_role_in(user, UserRole.ORG_ADMIN)

        from src.organizations.models import OrganizationStatus
        # TODO: results must be filtered by organizations pertaining to the admin
        stats = {
            "all": Organization.objects.count(),
            "active": Organization.objects.filter(status=OrganizationStatus.ACTIVE).count(),
            "suspended": Organization.objects.filter(status=OrganizationStatus.SUSPENDED).count(),
        }

        return self.create_response(message="Organizations statistics", data=stats, status_code=200)
