from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController

from src.api.exception_handler import attach_exception_handlers

from src.dids.did_registry_api.controllers.certificates_controller import (
    CertificatesController,
)
from src.dids.did_registry_api.controllers.keys_controller import KeysController
from src.dids.did_registry_api.controllers.publish_requests_controller import (
    PublishRequestsController,
)
from src.dids.did_registry_api.controllers.registry_controller import RegistryController
from src.dids.did_registry_api.controllers.universal_registrar_controller import (
    UniversalRegistrarController,
)
from src.diagnostics.controllers.publish_health_controller import (
    PublishHealthController,
)
from src.dids.resolver.controllers import ResolverController

from src.organizations.apis import OrganizationController
from src.users.apis import UserController

# from src.api_keys.apis import APIKeyController
from src.auditaction.apis import AuditActionController
from src.superadmin.apis import SuperAdminController
from src.auth.controllers.logout_controller import LogoutController


api = NinjaExtraAPI(title="DID Annuaire API", version="1.0.0", csrf=False)

# JWT Authentication
api.register_controllers(NinjaJWTDefaultController)

# Register exception handlers in one place
attach_exception_handlers(api)

api.register_controllers(
    SuperAdminController,
    OrganizationController,
    UserController,
    # APIKeyController,
    AuditActionController,
    RegistryController,
    KeysController,
    PublishRequestsController,
    UniversalRegistrarController,
    CertificatesController,
    ResolverController,
    LogoutController,
    PublishHealthController,
)
