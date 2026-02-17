from django.contrib.postgres.indexes import GinIndex
from django.db.models import CheckConstraint, Q
from django.db import models

from src.common.models import BaseModel


from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)


class UserRole(models.TextChoices):
    ORG_ADMIN = "ORG_ADMIN", "Organization Admin"
    ORG_MEMBER = "ORG_MEMBER", "Organization Member"
    AUDITOR = "AUDITOR", "Auditor"


class UserStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    INVITED = "INVITED", "Invited"
    ACTIVE = "ACTIVE", "Active"
    DEACTIVATED = "DEACTIVATED", "Deactivated"


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.update(
            {
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
                "status": UserStatus.ACTIVE,
                "organization": None,
            }
        )
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, BaseModel, PermissionsMixin):
    """Personnel des organisations (PAS les détenteurs de VCs)"""

    # Identification
    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    phone = models.CharField(max_length=50, blank=True)

    # Organization
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="users",
        null=True,
        blank=True,
    )  # Null pour SuperUser

    # Rôle et statut
    role = models.JSONField(
        default=list,
        help_text="List of role tokens (e.g., ['ORG_MEMBER','AUDITOR']).",
    )
    status = models.CharField(max_length=20, choices=UserStatus.choices)

    # Invitation
    invitation_token = models.CharField(max_length=255, blank=True, db_index=True)
    invitation_sent_at = models.DateTimeField(null=True, blank=True)
    invitation_accepted_at = models.DateTimeField(null=True, blank=True)
    invited_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="invited_users",
    )

    # 2FA -TOTP (Google Authenticator)
    totp_secret = models.CharField(max_length=255, blank=True)
    totp_enabled = models.BooleanField(default=False)

    # 2FA - Email OTP
    email_otp_code = models.CharField(max_length=6, blank=True)
    email_otp_expires_at = models.DateTimeField(null=True, blank=True)
    email_otp_sent_at = models.DateTimeField(null=True, blank=True)

    # 2FA - SMS OTP
    sms_otp_code = models.CharField(max_length=6, blank=True)
    sms_otp_expires_at = models.DateTimeField(null=True, blank=False)
    sms_otp_sent_at = models.DateTimeField(null=True, blank=True)

    # Password Reset
    password_reset_token = models.CharField(max_length=255, blank=True, db_index=True, unique=True, null=True)
    password_reset_token_expires_at = models.DateTimeField(null=True, blank=True)
    password_reset_token_created_at = models.DateTimeField(null=True, blank=True)

    # Permissions
    can_publish_prod = models.BooleanField(default=False)

    # Django required
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)

    # Détails supplémentaires requis pour le futur admin d'une organization
    functions = models.CharField(max_length=150, blank=True)

    refusal_reason = models.TextField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        db_table = "users"
        verbose_name = "User"
        verbose_name_plural = "Users"
        constraints = [
            CheckConstraint(
                check=Q(is_superuser=True, organization__isnull=True)
                | Q(is_superuser=False),
                name="superuser_requires_null_org",
            )
        ]
        indexes = [
            GinIndex(
                fields=["role"], name="user_role_gin", opclasses=["jsonb_path_ops"]
            ),
        ]

    def __str__(self):
        return (
            f"{self.email} {[self.role]}"
            if self.role
            else f"{self.email} [SUPER_ADMIN]"
        )

    @property
    def is_platform_admin(self):
        return self.is_superuser

    @property
    def is_org_admin(self) -> bool:
        return UserRole.ORG_ADMIN.value in self.role

    @property
    def can_publish_prod_effective(self) -> bool:
        return self.is_org_admin or self.can_publish_prod

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        self.is_active = self.status == UserStatus.ACTIVE
        super().save(*args, **kwargs)
