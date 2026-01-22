from django.db import models
from django.db.models import Q

from src.common.models import BaseModel
from src.organizations.models import Organization


class DID(BaseModel):
    """
    Stable decentralized identifier (did:web).
    Does not change once created.
    """

    class DIDStatus(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        ACTIVE = "ACTIVE", "Active"
        DEACTIVATED = "DEACTIVATED", "Deactivated"

    did = models.CharField(
        max_length=500,
        unique=True,
        help_text="did:web:domain:{org}:{user}:{document_type}",
    )

    method = models.CharField(max_length=20, default="web", help_text="DID method")

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="dids"
    )

    owner = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="owned_dids"
    )

    document_type = models.CharField(
        max_length=150,
        help_text="Logical document identifier (e.g. permis_conduite_qrcode)",
    )

    status = models.CharField(
        max_length=20,
        choices=DIDStatus.choices,
        default=DIDStatus.DRAFT,
        db_index=True,
    )

    class Meta:
        # verbose_name = "DIDs"
        pass

    def __str__(self):
        return self.did


class DIDDocument(BaseModel):
    """
    Versioned W3C DID Document.
    Immutable once published.
    """

    did = models.ForeignKey(DID, on_delete=models.CASCADE, related_name="documents")

    version = models.PositiveIntegerField(
        help_text="Monotonically increasing version number"
    )

    document = models.JSONField(help_text="Canonical W3C DID Document JSON")

    proof = models.JSONField(
        null=True,
        blank=True,
        help_text="Cryptographic proof added before publication (Linked Data Proof) JsonWebSignature2020 proof",
    )

    environment = models.CharField(
        max_length=20,
        choices={
            "DRAFT": "Draft",
            "PREPROD": "Pré-production",
            "PROD": "Production",
        },
        default="DRAFT",
    )

    published_at = models.DateTimeField(null=True, blank=True)
    published_by = models.ForeignKey(
        "users.User",
        null=True,
        on_delete=models.SET_NULL,
        related_name="published_documents",
    )

    is_active = models.BooleanField(
        default=False, help_text="Only one active document per DID & environment"
    )

    # Publication metadata & integrity
    canonical_sha256 = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="JCS (RFC8785) SHA-256 of the JSON document in DRAFT",
    )
    file_sha256 = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="SHA-256 of published did.json (PREPROD/PROD)",
    )
    file_etag = models.CharField(
        max_length=128, null=True, blank=True, help_text="ETag of did.json if available"
    )
    published_relpath = models.TextField(
        null=True,
        blank=True,
        help_text="Relative path under /.well-known (e.g., preprod/{org}/{user}/{type}/did.json)",
    )

    class Meta:
        ordering = ["-version"]
        constraints = [
            models.UniqueConstraint(
                fields=["did", "version"], name="did_document_version_unique"
            ),
            models.UniqueConstraint(
                fields=["did", "environment"],
                condition=Q(is_active=True),
                name="unique_active_diddoc_per_env",
            ),
        ]

    def __str__(self):
        return f"{self.did.did}@v{self.version}({self.environment})"


class Certificate(BaseModel):
    """
    Certificat ou conteneur cryptographique fourni par l’utilisateur.
    Sert uniquement à extraire une clé publique JWK.
    """

    class CertFormat(models.TextChoices):
        PEM = "PEM", "PEM"
        DER = "DER", "DER"
        PKCS7 = "PKCS7", "PKCS#7"
        PKCS12 = "PKCS12", "PKCS#12"

    owner = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="certificates"
    )

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    file = models.FileField(upload_to="certificates/%Y/%m/")

    format = models.CharField(max_length=20, choices=CertFormat.choices)

    extracted_jwk = models.JSONField(help_text="Clé publique normalisée au format JWK")

    fingerprint = models.CharField(
        max_length=128, unique=True, help_text="SHA-256 fingerprint"
    )

    is_revoked = models.BooleanField(default=False)


class UploadedPublicKey(BaseModel):
    """
    Cryptographic material used in DID Documents.
    A given (did, key_id) can have several versions over time (rotation).
    """

    did = models.ForeignKey(DID, on_delete=models.CASCADE, related_name="keys")

    key_id = models.CharField(max_length=100, help_text="Fragment id, e.g. key-1")

    class KeyType(models.TextChoices):
        JSON_WEB_KEY_2020 = "JsonWebKey2020", "JsonWebKey2020"

    key_type = models.CharField(
        max_length=50,
        choices=KeyType.choices,  # JWK (EC P-256/P-384, RSA 2048/3072)
    )

    version = models.PositiveIntegerField(default=1, db_index=True)

    certificate = models.ForeignKey(
        Certificate, on_delete=models.CASCADE, related_name="did_keys"
    )

    public_key_jwk = models.JSONField(help_text="Normalized public key (JWK only)")

    public_key_jwk_snapshot = models.JSONField(
        help_text="Frozen copy of the JWK as used in a specific DID Document version"
    )

    purposes = models.JSONField(
        default=list, help_text="authentication, assertionMethod, keyAgreement, etc."
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "public_keys"
        verbose_name = "Public Key"
        verbose_name_plural = "Public Keys"
        constraints = [
            models.UniqueConstraint(
                fields=["did", "key_id", "version"], name="did_keyid_version_unique"
            ),
        ]

    def __str__(self):
        return f"{self.did.did}#{self.key_id}@v{self.version}"


class PublishRequest(BaseModel):
    """
    User request to publish a DIDDocument to PREPROD/PROD requiring approval.
    """

    class Env(models.TextChoices):
        PREPROD = "PREPROD", "Pre-production"
        PROD = "PROD", "Production"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    did = models.ForeignKey(
        DID, on_delete=models.CASCADE, related_name="publish_requests"
    )
    did_document = models.ForeignKey(
        DIDDocument, on_delete=models.CASCADE, related_name="publish_requests"
    )
    environment = models.CharField(max_length=10, choices=Env.choices)
    requested_by = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="requested_publish"
    )
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.PENDING
    )
    decided_by = models.ForeignKey(
        "users.User",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="decided_publish",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField(blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["did", "environment", "status"]),
        ]

    def __str__(self):
        return f"PublishRequest(did={self.did_id}, env={self.environment}, status={self.status})"


class DidDocumentKeyBinding(BaseModel):
    did_document = models.ForeignKey(
        "dids.DIDDocument", on_delete=models.CASCADE, related_name="key_bindings"
    )
    uploaded_public_key = models.ForeignKey(
        "dids.UploadedPublicKey", on_delete=models.CASCADE, related_name="doc_bindings"
    )
    purposes_snapshot = models.JSONField(default=list)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["did_document", "uploaded_public_key"],
                name="doc_keybinding_unique",
            )
        ]

    def __str__(self):
        return f"Doc {self.did_document_id} uses {self.uploaded_public_key_id}"
