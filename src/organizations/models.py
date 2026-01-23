from django.db import models

from src.common.models import BaseModel


class OrganizationStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    ACTIVE = "ACTIVE", "Active"
    REFUSED = "REFUSED", "Refused"
    SUSPENDED = "SUSPENDED", "Suspended"


class Organization(BaseModel):
    # Identification
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=100, unique=True, db_index=True)

    # Type and country
    type = models.CharField(
        max_length=50,
        choices={
            "ADMINISTRATION": "Administration",
            "ENTREPRISE": "Enterprise",
            "PSCE": "PSCE",
            "OTHER": "Other",
        },
        default="Other",
    )
    country = models.CharField(max_length=50)

    # Contact
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=50, blank=True, default="")
    address = models.TextField(blank=True)

    # Domaines email autorisés
    allowed_email_domains = models.JSONField(
        default=list, help_text="Liste des domaines email autorisées"
    )

    # Documents
    justification_document = models.FileField(
        upload_to="organizations/justifications/",
        blank=True,
        null=True,
        help_text="Document de justification",
    )
    authorization_document = models.FileField(
        upload_to="organizations/authorizations/",
        help_text="Autorisation de l’organisation (document signé par le représentant légal de l’organisation)"
    )

    # Statut
    status = models.CharField(
        max_length=20,
        choices=OrganizationStatus.choices,
        default=OrganizationStatus.PENDING,
        db_index=True,
    )

    # Validation
    validated_at = models.DateTimeField(null=True, blank=True)
    validated_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="validated_organizations",
    )  # why not related_name='+'

    # Refus
    refused_at = models.DateTimeField(null=True, blank=True)
    refused_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refused_organizations",
    )  # not related_name='+'
    refusal_reason = models.TextField(blank=True)

    class Meta:
        db_table = "organizations"
        verbose_name = "Organisation"
        verbose_name_plural = "Organisations"
        constraints = [
            models.UniqueConstraint(fields=["email"], name="org_email_unique"),
            models.UniqueConstraint(fields=["slug"], name="org_slug_unique"),
        ]

    def __str__(self):
        return self.name
