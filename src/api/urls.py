from __future__ import annotations

from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController

api = NinjaExtraAPI(title="DID Annuaire API", version="1.0.0")

# JWT Authentication
api.register_controllers(NinjaJWTDefaultController)

from src.organizations.apis import OrganizationController
from src.users.apis import UserController
from src.dids.apis import ApplicationController, DIDController
from src.api_keys.apis import APIKeyController
from src.auditaction.apis import AuditActionController
from src.superadmin.apis import SuperAdminController

# Register exception handlers in one place
from src.api.exception_handler import attach_exception_handlers

attach_exception_handlers(api)

api.register_controllers(
    SuperAdminController,
    OrganizationController,
    UserController,
    ApplicationController,
    DIDController,
    APIKeyController,
    AuditActionController,
)
