import uuid

from django.shortcuts import get_object_or_404
from ninja import Body, Query
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth

from src.api.pagination import Paginator
from src.common.utils import validate_uuid
from src.core.apis import BaseAPIController
from src.core.exceptions import APIError, DomainValidationError
from src.core.policies import ensure_role_in
from src.users import selectors, services
from src.users.models import User, UserRole, UserStatus
from src.users.schemas import (
    FilterParams,
    OrganizationInfo,
    UserActivatePayload,
    UserCreatePayload,
    UserListItem,
    UserProfileSchema,
    UserUpdatePayload,
)


@api_controller("/users", tags=["Users"], auth=JWTAuth())
class UserController(BaseAPIController):
    @route.post("/") # ✅
    def create_user(self, body: UserCreatePayload = Body(...)):
        current_user = self.context.request.auth
        try:
            user = services.user_create_by_admin(
                organization=current_user.organization,
                created_by=current_user,
                email=body.email,
                first_name=body.first_name,
                last_name=body.last_name,
                phone=(body.phone or "").strip(),
                is_auditor=body.is_auditor,
                functions=body.functions,
                can_publish_prod=body.can_publish_prod,
            )
        except PermissionError:
            return self.create_response(
                message="Only ORG_ADMIN can create users",
                status_code=403,
                code="FORBIDDEN",
            )

        return self.create_response(
            message="User created successfully",
            data={
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "status": user.status,
            },
            status_code=201,
        )

    @route.get("/") # ✅
    def list_users(self, filters: Query[FilterParams]):
        user = self.context.request.auth

        qs = selectors.user_list(
                user=user,
                status=filters.status,
                search=filters.search,
            )

        paginator = Paginator(default_page_size=10, max_page_size=100)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [UserListItem(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            status=u.status,
            created_at=u.created_at,
            organization=u.organization.name if u.organization else None,
            invited_by=u.invited_by.email if u.invited_by else None,
            functions=u.functions,
            invitation_accepted_at=u.invitation_accepted_at,
            can_publish_prod=u.can_publish_prod,
        ) for u in items]

        return self.create_response(
            message="Users fetched",
            data={"items": data, "pagination": meta},
            status_code=200,
        )
 
    @route.get("/me") # ✅
    def get_current_user(self):
        user = self.context.request.auth
        user_data = UserProfileSchema(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            phone=user.phone,
            role=user.role,
            status=user.status,
            organization=OrganizationInfo(
                id=user.organization.id if user.organization else None,
                name=user.organization.name if user.organization else None,
            ),
            totp_enabled=user.totp_enabled,
            last_login=user.last_login,
            can_publish_prod=user.can_publish_prod,
            functions=getattr(user, "functions", None),
        )
        return self.create_response(
            message="Current user",
            data=user_data.dict(),
            status_code=200,
        )
    
    @route.get("/{user_id}/info")
    def get_user_info(self, user_id: uuid.UUID):
        request_user = self.context.request.auth
        user_data = selectors.user_get_info(user_id=user_id, requesting_user=request_user)
        return self.create_response(
            data=user_data,
            status_code=200,
        )
    
    @route.post("/{user_id}/invite") # ✅
    def send_invitation(self, user_id: str):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN)

        user = get_object_or_404(
            User, id=user_id, organization=current_user.organization
        )
        services.user_send_invitation(user=user, invited_by=current_user)
        return self.create_response(message="Invitation sent successfully", status_code=200)

    @route.post("/activate", auth=None)
    def activate_account(self, payload: UserActivatePayload):
        """
        Activation flow:
          - enable_totp=False & code=None -> send email OTP (202 OTP_REQUIRED)
          - enable_totp=False & code provided -> verify OTP and activate (201)
          - enable_totp=True & no code -> generate TOTP QR (202 TOTP_REQUIRED)
          - enable_totp=True & code provided -> verify TOTP and activate (201)
        """
        try:
            user = services.user_get_invited_by_token(token=payload.token)

            if payload.enable_totp:
                # Prepare QR if TOTP not set or no code provided
                if not user.totp_secret or not payload.code:
                    qr = services.user_generate_totp_qr(user=user)
                    return self.create_response(
                        message="TOTP required: scan the QR and submit the code to activate",
                        data={"totp_qr": qr},
                        status_code=202,
                        code="TOTP_REQUIRED",
                    )
                # Verify TOTP then activate
                services.verify_otp(user=user, otp_type="totp", provided_code=payload.code)
                user = services.user_activate_account(
                    token=payload.token, password=payload.password, enable_totp=True
                )
                return self.create_response(
                    message="Account activated successfully",
                    data={"user": {"email": user.email, "full_name": user.full_name}},
                    status_code=201,
                )

            # enable_totp=False branch
            if not payload.code:
                # generate OTP and return 202
                services.user_generate_otp(user=user, otp_type="email")
                return self.create_response(
                    message="Activation OTP sent. Please verify to activate your account.",
                    data={"otp_sent_to": user.email},
                    status_code=202,
                    code="OTP_REQUIRED",
                )

            # verify OTP then activate
            services.verify_otp(user=user, otp_type="email", provided_code=payload.code)
            user = services.user_activate_account(
                token=payload.token, password=payload.password, enable_totp=False
            )
            return self.create_response(
                message="Account activated successfully",
                data={"user": {"email": user.email, "full_name": user.full_name}},
                status_code=201,
            )

        except DomainValidationError as e:
            return self.create_response(message=e.message, status_code=400, code=e.code)

#    @route.post("/otp/sms/generate")
#    def generate_sms_otp(self):
#        user = self.context.request.auth
#        services.user_generate_otp(user=user, otp_type="sms")
#        return self.create_response(message="SMS OTP sent", status_code=200)

#    @route.post("/otp/sms/verify")
#    def verify_sms_otp(self, payload: OTPVerifyPayload):
#        user = self.context.request.auth
#        verify_otp(user=user, otp_type="sms", provided_code=payload.code)
#        return self.create_response(message="SMS OTP verified", status_code=200)

    @route.post("/{user_id}/toggle")
    def toggle_user(self, user_id: str): # ✅
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN)

        try:
            user = services.user_toggle_active(user_id=user_id, toggled_by=current_user)
        except PermissionError as e:
            return self.create_response(message=str(e), status_code=403, code="FORBIDDEN")
        except DomainValidationError as e:
            return self.create_response(message=e.message, status_code=400, code=e.code)
        except User.DoesNotExist:
            return self.create_response(message="User not found", status_code=404, code="NOT_FOUND")

        verb = "activated" if user.status == UserStatus.ACTIVE else "deactivated"
        return self.create_response(
            message=f"User {verb} successfully",
            data={"id": str(user.id), "status": user.status},
            status_code=200,
        )

    @route.patch("/{user_id}/update")
    def update_user(self, user_id: str, payload: UserUpdatePayload):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth

        # TODO: ALLOW superuser to update user info
        ensure_role_in(current_user, UserRole.ORG_ADMIN, UserRole.ORG_MEMBER)

        services.user_update_user(
            user_id=user_id,
            updated_by=current_user,
            payload=payload
        )

        return self.create_response(
            message="User updated successfully",
            status_code=200,
        )

    @route.get("/stats")
    def users_stats(self):
        user = self.context.request.auth
    
        stats = selectors.users_stats_for_actor(user=user)
    
        return self.create_response(
            message="Users statistics",
            data=stats,
            status_code=200,
        )
        
    @route.delete("/{user_id}")
    def delete_user(self, user_id: uuid.UUID):
        request_user = self.context.request.auth
        services.user_delete(user_id=user_id, requesting_user=request_user)
        return self.create_response(message="User deleted successfully", status_code=200)
    
    # TODO: Reset password,