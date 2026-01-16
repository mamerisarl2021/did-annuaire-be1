from __future__ import annotations

from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController

from src.api.exception_handler import attach_exception_handlers
from src.dids.api_certificates import CertificateController
from src.dids.api_registry_create import DIDCreationController
from src.dids.apis_registry import RegistryController

from src.organizations.apis import OrganizationController
from src.users.apis import UserController
from src.dids.apis_universal import UniversalRegistrarController, UniversalResolverController
from src.dids.apis_version_service import VersionServiceController
from src.api_keys.apis import APIKeyController
from src.auditaction.apis import AuditActionController
from src.superadmin.apis import SuperAdminController

api = NinjaExtraAPI(title="DID Annuaire API", version="1.0.0")

# JWT Authentication
api.register_controllers(NinjaJWTDefaultController)

# Register exception handlers in one place
attach_exception_handlers(api)

api.register_controllers(
    SuperAdminController,
    OrganizationController,
    UserController,
    APIKeyController,
    AuditActionController,
    UniversalRegistrarController,
    UniversalResolverController,
    VersionServiceController,
    RegistryController,
    CertificateController,
    DIDCreationController,

)
