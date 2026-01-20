import uuid

from ninja import Schema


class DidDocument1(Schema):
    didRecordId: str | None = None
    did: str
    documentContent: dict
    documentMetadata: dict | None = None


class DidVersion(Schema):
    didRecordId: str | None = None
    did: str
    versionId: str
    versionTime: int | None = None
    versionMetadata: dict | None = None


class DidState1(Schema):
    didRecordId: str = None
    did: str
    state: str
    stateTime: int | None = None
    stateMetadata: dict | None = None


class DidRecord(Schema):
    id: str | None = None
    timestamp: int | None = None
    did: str
    method: str
    didDocument: DidDocument1 | None = None
    didVersion: DidVersion | None = None
    didState: DidState1 | None = None


########################################################################################3


class CreateRequest(Schema):
    didDocument: dict
    options: dict | None = None
    secret: dict | None = None


class RegistrarState(Schema):
    jobId: str | None = None
    didState: dict
    didRegistrationMetadata: dict | None = None
    didDocumentMetadata: dict | None = None


class UpdateRequest(Schema):
    did: str
    didDocumentOperation: list[str]
    didDocument: list[dict]


class DeactivateRequest(Schema):
    did: str


##########################################################################


class PublishResponse(Schema):
    did: str
    environment: str
    version: int
    url: str | None = None
    state: str


class ValidateResponse(Schema):
    did: str
    version: int
    valid: bool
    canonical_sha256: str


class PublishRequestOut(Schema):
    id: int
    did: str
    version: int
    environment: str
    status: str
    requested_by: str
    decided_by: str | None = None
    decided_at: str | None = None
    note: str | None = None


###########################################################


class CertificateOut(Schema):
    id: uuid.UUID
    format: str
    fingerprint: str
    extracted_jwk: dict


###########################################################


class KeyInput(Schema):
    certificate_id: uuid.UUID
    key_id: str
    purposes: list[str] | None = None


###############################################################


class CreateDIDRequest(Schema):
    organization_id: uuid.UUID
    document_type: str
    # legacy single-key params (still supported)
    certificate_id: int | None = None
    key_id: str | None = None
    purposes: list[str] | None = None
    # multi-key mode
    keys: list[KeyInput] | None = None
    owner_id: uuid.UUID | None = None
    services: list[dict] | None = None


class CreateDIDResponse(Schema):
    did: str
    did_document_version: int
    environment: str
    uploaded_public_key_id: uuid.UUID


########################################################


class PreviewDIDResponse(Schema):
    did: str
    document: dict
    canonical_sha256: str
    did_url_preprod: str
    did_url_prod: str

    # En bonus pour le FE (facultatif)
    organization_slug: str
    user_slug: str
    document_type: str

    # Index de la vm clé utilisée (utile au FE)
    key_id: str


class PreviewDIDRequest(Schema):
    organization_id: uuid.UUID
    document_type: str
    # either legacy:
    certificate_id: uuid.UUID = None
    key_id: str | None = None
    purposes: list[str] | None = None
    # or multi:
    keys: list[KeyInput] | None = None
