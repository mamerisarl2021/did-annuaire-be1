from django.db import models
from src.common.models import BaseModel


class AuditCategory(models.TextChoices):
    ORGANIZATION = "ORGANIZATION", "Organization"
    USER = "USER", "User"
    DID = "DID", "DID"
    KEY = "KEY", "Key"
    API = "API", "API"
    AUTH = "AUTH", "Authentication"
    SYSTEM = "SYSTEM", "System"


class Severity(models.TextChoices):
    INFO = "INFO", "Info"
    WARNING = "WARNING", "Warning"
    ERROR = "ERROR", "Error"
    CRITICAL = "CRITICAL", "Critical"


class AuditAction(models.TextChoices):
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS", "Login success"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED", "Login Failed"
    AUTH_LOGOUT = "AUTH_LOGOUT", "Logout"

    # Organisations
    ORG_CREATED = "ORG_CREATED", "Organisation créée"
    ORG_VALIDATED = "ORG_VALIDATED", "Organisation validée"
    ORG_REFUSED = "ORG_REFUSED", "Organisation refusée"
    ORG_SUSPENDED = "ORG_SUSPENDED", "Organisation suspendue"
    ORG_DELETED = "ORG_DELETED", "Organization supprimé"
    ORGANIZATION_TOGGLED_ACTIVATION = (
        "ORGANIZATION_TOGGLED_ACTIVATION",
        "Organization status toggled",
    )

    # Utilisateurs
    USER_INVITED = "USER_INVITED", "Utilisateur invité"
    USER_ACTIVATED = "USER_ACTIVATED", "Utilisateur activé"
    USER_LOGIN = "USER_LOGIN", "Connexion utilisateur"
    USER_LOGOUT = "USER_LOGOUT", "Déconnexion utilisateur"
    USER_SUSPENDED = (
        "USER_SUSPENDED",
        "Utilisateur suspendu",
    )
    USER_CREATED = "USER_CREATED", "Création Utilisateur"
    USER_UPDATED = "USER_UPDATED", "Mise à jour utilisateur"
    USER_DELETED = "USER_DELETED", "Suppression utilisateur"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Réinitialisation mot de passe demandée"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED", "Mot de passe réinitialisé"
    PASSWORD_RESET_FAILED = "PASSWORD_RESET_FAILED", "Échec réinitialisation mot de passe"

    # DIDs
    DID_CREATED = "DID_CREATED", "DID créé"
    DID_PUBLISHED_DRAFT = "DID_PUBLISHED_DRAFT", "DID publié en draft"
    DID_PUBLISHED_PUBLIC = "DID_PUBLISHED_PUBLIC", "DID publié publiquement"
    PUBLISH_REQUEST_APPROVED = "PUBLISH_REQUEST_APPROVED", "Publication did Acccepté"
    PUBLISH_REQUEST_REJECTED = "PUBLISH_REQUEST_REJECTED", "Publication did rejeté"
    DID_REVOKED = "DID_REVOKED", "DID révoqué"

    # Clés et certificats
    KEY_UPLOADED = "KEY_UPLOADED", "Clé/certificat ajouté"
    KEY_DELETED = "KEY_DELETED", "Clé/certificat supprimé"

    # API
    API_KEY_CREATED = "API_KEY_CREATED", "Clé API créée"
    API_KEY_REVOKED = "API_KEY_REVOKED", "Clé API révoquée"

    # Email services
    EMAIL_SENT = "EMAIL_SENT", "Email delivered"
    EMAIL_SEND_FAILED = "EMAIL_SEND_FAILED", "Email delivery failed"
    OTP_GENERATED = "OTP_GENERATED", "OTP generated"

    ADMIN_NOT_FOUND = "ORG_ADMIN_NOT_FOUNDOrganization admin not found"

    # Celery tasks


class AuditLog(BaseModel):
    """
    Journal d'audit pour tracer toutes les actions importantes
    """

    # Acteur/Où
    user = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_actions",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_actions",
    )
    # Quoi
    category = models.CharField(
        max_length=32, choices=AuditCategory.choices, default=AuditCategory.SYSTEM
    )
    action = models.CharField(max_length=50, choices=AuditAction.choices, db_index=True)

    # Cible Optionnelle
    target_type = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Type de ressource: 'user', 'organization', 'did', etc.",
    )
    target_id = models.CharField(
        max_length=255, blank=True, null=True, help_text="ID de la ressource affectée"
    )

    # Contexte
    details = models.JSONField(
        default=dict, blank=True, help_text="Informations contextuelles supplémentaires"
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.INFO
    )

    # Métadonnées de la requềte
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "action", "-created_at"]),
            models.Index(fields=["category", "-created_at"]),
            models.Index(fields=["action"]),
            models.Index(fields=["user"]),
            models.Index(fields=["target_type", "target_id"]),
        ]

    def __str__(self) -> str:
        actor = self.user.email if self.user else "system"
        target = f"{self.target_type}:{self.target_id}" if self.target_type else ""
        return f"[{self.category}] {self.action} by {actor} {target} at {self.created_at:%Y-%m-%d %H:%M:%S}"
