from ninja import Form, Query
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth
from django.shortcuts import get_object_or_404

from src.api.pagination import Paginator
from src.common.utils import validate_uuid
from src.core.apis import BaseAPIController
from src.core.exceptions import DomainValidationError
from src.core.policies import ensure_role_in
from src.users.models import User, UserRole
from src.users import services, selectors
from src.users.presenters import user_to_list_dto, user_to_detail_dto
from src.users.schemas import (
    UserCreatePayload,
    UserActivatePayload,
    UserUpdatePayload,
    OTPVerifyPayload,
    UserFilterParams,
)


@api_controller("/users", tags=["Users"], auth=JWTAuth())
class UserController(BaseAPIController):
    @route.post("/")
    def create_user(self, payload: UserCreatePayload = Form(...)):
        current_user = self.context.request.auth
        if current_user.role != UserRole.ORG_ADMIN:
            return self.create_response(
                message="Only ORG_ADMIN can create users",
                status_code=403,
                code="FORBIDDEN",
            )

        user = services.user_create_by_admin(
            organization=current_user.organization,
            created_by=current_user,
            email=payload.email,
            first_name=payload.first_name,
            last_name=payload.last_name,
            phone=payload.phone,
            role=payload.role,
            functions=payload.functions,
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

    @route.get("/")
    def list_users(self, filters: Query[UserFilterParams]):  # ← MODIFIÉ
        """
        Liste les utilisateurs de mon organisation
        Supporte: status, role, search + pagination
        """
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN, UserRole.SUPERUSER)

        qs = selectors.user_list(
            organization=current_user.organization,
            status=filters.status,
            role=filters.role,
            search=filters.search,
        )

        # ← PAGINATION AJOUTÉE
        paginator = Paginator(default_page_size=20, max_page_size=100)
        items, meta = paginator.paginate_queryset(qs, self.context.request)

        data = [user_to_list_dto(u) for u in items]
        return self.create_response(
            message="Users fetched",
            data={"items": data, "pagination": meta},  # ← FORMAT AVEC PAGINATION
            status_code=200,
        )

    @route.get("/me")
    def get_current_user(self):
        return self.create_response(
            message="Current user",
            data=user_to_detail_dto(self.context.request.auth),
            status_code=200,
        )

    @route.post("/{user_id}/invite")
    def send_invitation(self, user_id: str):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN)

        user = get_object_or_404(
            User, id=user_id, organization=current_user.organization
        )
        services.user_send_invitation(user=user, invited_by=current_user)
        return self.create_response(
            message="Invitation sent successfully", status_code=200
        )

    @route.post("/activate", auth=None)
    def activate_account(self, payload: UserActivatePayload):
        """
        Flux:
          - enable_totp=False -> activation directe.
          - enable_totp=True et pas de code -> préparer TOTP (si nécessaire) et renvoyer le QR (202 TOTP_REQUIRED).
          - enable_totp=True et code -> vérifier TOTP puis activer.
        """
        try:
            # Récupérer l’utilisateur invité et vérifier l’expiration du lien
            user = services.user_get_invited_by_token(token=payload.token)

            if payload.enable_totp:
                # S'assurer que le secret existe; si pas encore initialisé, le générer et renvoyer le QR sans activer
                if not user.totp_secret:
                    # Génère le secret si absent (user_generate_totp_qr crée le secret si besoin)
                    qr = services.user_generate_totp_qr(user=user)
                    return self.create_response(
                        message="TOTP requis: scannez le QR et renvoyez le code pour activer",
                        data={"totp_qr": qr},
                        status_code=202,
                        code="TOTP_REQUIRED",
                    )

                # Si un code est fourni, on le vérifie, puis on active
                if payload.code:
                    services.user_verify_totp_or_raise(user=user, code=payload.code)
                    user = services.user_activate_account(
                        token=payload.token,
                        password=payload.password,
                        enable_totp=True,
                    )
                    return self.create_response(
                        message="Account activated successfully",
                        data={
                            "user": {"email": user.email, "full_name": user.full_name}
                        },
                        status_code=201,
                    )

                # Secret déjà présent mais pas de code -> renvoyer le QR (toujours sans activer)
                qr = services.user_generate_totp_qr(user=user)
                return self.create_response(
                    message="TOTP requis: scannez le QR et renvoyez le code pour activer",
                    data={"totp_qr": qr},
                    status_code=202,
                    code="TOTP_REQUIRED",
                )

            # Cas sans TOTP -> activation directe
            user = services.user_activate_account(
                token=payload.token,
                password=payload.password,
                enable_totp=False,
            )
            return self.create_response(
                message="Account activated successfully",
                data={"user": {"email": user.email, "full_name": user.full_name}},
                status_code=201,
            )

        except DomainValidationError as e:
            return self.create_response(message=e.message, status_code=400, code=e.code)
        except ValueError as e:
            return self.create_response(
                message=str(e), status_code=400, code="BAD_REQUEST"
            )

    @route.post("/{user_id}/deactivate")
    def deactivate_user(self, user_id: str):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN, UserRole.SUPERUSER)

        services.user_deactivate(user_id=user_id, deactivated_by=current_user)
        return self.create_response(
            message="User deactivated successfully", status_code=200
        )

    @route.patch("/{user_id}/update")
    def update_user(self, user_id: str, payload: UserUpdatePayload):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth

        user = services.user_update(
            user_id=user_id,
            updated_by=current_user,
            first_name=payload.first_name,
            last_name=payload.last_name,
            phone=payload.phone,
            role=payload.role,
            functions=payload.functions,
            status=payload.status,
        )
        return self.create_response(
            message="User updated",
            data={
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "status": user.status,
                "functions": getattr(user, "functions", None),
            },
            status_code=200,
        )

    @route.post("/{user_id}/resend-invite")
    def resend_invitation(self, user_id: str):
        user_id = validate_uuid(user_id)
        current_user = self.context.request.auth
        ensure_role_in(current_user, UserRole.ORG_ADMIN, UserRole.SUPERUSER)

        services.user_resend_invitation(user_id=user_id, requested_by=current_user)
        return self.create_response(message="Invitation re-sent", status_code=200)

    @route.post("/otp/email/generate")
    def generate_email_otp(self):
        u = self.context.request.auth
        services.user_generate_email_otp(user=u)
        return self.create_response(message="Email OTP sent", status_code=200)

    @route.post("/otp/email/verify")
    def verify_email_otp(self, payload: OTPVerifyPayload):
        u = self.context.request.auth
        # Will raise DomainValidationError("OTP_EXPIRED"/"OTP_INVALID") if not OK
        services.user_verify_email_otp(user=u, code=payload.code)
        return self.create_response(message="OTP verified", status_code=200)
