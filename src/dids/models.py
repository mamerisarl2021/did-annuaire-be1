from django.db import models

from src.common.models import BaseModel


class Application(BaseModel):
    """Cas d'usage pour lequel un DID est créé"""

    name = models.CharField(max_length=255)  # Ex: "ePassport", "DriverLicense"
    slug = models.SlugField(max_length=100)  # Pour le DID path
    description = models.TextField(blank=True)

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="applications",
    )
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_applications",
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "applications"
        unique_together = [["organization", "slug"]]
        verbose_name = "Application"
        verbose_name_plural = "Applications"

    def __str__(self):
        return f"{self.organization.name} - {self.name}"


class DIDDocument(BaseModel):
    """Document DID W3C généré automatiquement par la plateforme"""

    # DID complet: did:web:annuairedid-fe.qcdigitalhub.com:org:user:app
    did = models.CharField(max_length=500, unique=True, db_index=True)

    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="did_documents"
    )
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_did_documents",
    )

    # Input utilisateur (usage futur non défini)
    domain = models.CharField(
        max_length=255, help_text="Domaine saisi par l'utilisateur (usage futur)"
    )

    # Contenu
    document = models.JSONField()  # Le DID Document W3C complet
    version = models.IntegerField(default=1)

    # Statuts
    status = models.CharField(
        max_length=20,
        choices=[
            ("DRAFT", "Brouillon"),
            ("PREPROD", "Pré-production"),
            ("PUBLISHED", "Publié"),
            ("REVOKED", "Révoqué"),
        ],
        default="DRAFT",
        db_index=True,
    )

    # Workflow preprod
    preprod_published_at = models.DateTimeField(null=True, blank=True)
    preprod_published_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="preprod_published_dids",
    )

    # Validation admin org
    validated_at = models.DateTimeField(null=True, blank=True)
    validated_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="validated_dids",
    )

    # Publication production
    prod_published_at = models.DateTimeField(null=True, blank=True)
    prod_published_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="prod_published_dids",
    )

    # Révocation
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_dids",
    )
    revocation_reason = models.TextField(blank=True)

    class Meta:
        db_table = "did_documents"
        ordering = ["-created_at"]
        verbose_name = "DID Document"
        verbose_name_plural = "DID Documents"
        constraints = [
            models.UniqueConstraint(fields=["did"], name="did_document_did_unique"),
        ]

    def __str__(self):
        return self.did


class PublicKey(BaseModel):
    """Clés publiques/certificats uploadés par les utilisateurs"""

    did_document = models.ForeignKey(
        DIDDocument, on_delete=models.CASCADE, related_name="public_keys"
    )

    key_id = models.CharField(max_length=100)  # Ex: "#key-1"
    key_type = models.CharField(
        max_length=50,
        choices=[
            ("Ed25519VerificationKey2020", "Ed25519"),
            ("JsonWebKey2020", "JWK (RSA/EC)"),
            ("EcdsaSecp256k1VerificationKey2019", "secp256k1"),
            ("RsaVerificationKey2018", "RSA"),
        ],
    )

    # Formats de clé publique
    public_key_pem = models.TextField(blank=True)
    public_key_jwk = models.JSONField(null=True, blank=True)
    public_key_multibase = models.TextField(blank=True)

    # Certificat original
    certificate_file = models.FileField(
        upload_to="certificates/%Y/%m/", help_text="Fichier certificat original uploadé"
    )

    # Métadonnées
    controller = models.CharField(max_length=500)
    purposes = models.JSONField(
        default=list, help_text="['authentication', 'assertionMethod', etc.]"
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "public_keys"
        verbose_name = "Public Key"
        verbose_name_plural = "Public Keys"
        constraints = [
            models.UniqueConstraint(
                fields=["did_document", "key_id"], name="did_key_ref_unique"
            ),
        ]

    def __str__(self):
        return f"{self.did_document.did}{self.key_id}"
