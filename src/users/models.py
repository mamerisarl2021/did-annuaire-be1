from src.common.models import BaseModel

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models


class UserRole(models.TextChoices):
    SUPERUSER = 'SUPERUSER', 'Super Utilisateur'
    ORG_ADMIN = 'ORG_ADMIN', 'Admin Organisation'
    ORG_MEMBER = 'ORG_MEMBER', 'Membre Organisation'
    AUDITOR = 'AUDITOR', 'Auditeur'


class UserStatus(models.TextChoices):
    PENDING = "PENDING", "En Attente"
    INVITED = 'INVITED', 'Invité'
    ACTIVE = 'ACTIVE', 'Actif'
    DEACTIVATED = 'SUSPENDED', 'Désactivé'


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
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault('role', UserRole.SUPERUSER)
        extra_fields.setdefault('status', UserStatus.ACTIVE)

        return self.create_user(email=email, password=password, **extra_fields)


class User(AbstractBaseUser, BaseModel, PermissionsMixin):
    """Personnel des organisations (PAS les détenteurs de VCs)"""

    # Identification
    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    phone = models.CharField(max_length=50, blank=True)

    # Organization
    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE, related_name='users',
                                     null=True, blank=True) # Null pour SuperUser

    # Rôle et statut
    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.ORG_MEMBER, db_index=True)
    status = models.CharField(max_length=20, choices=UserStatus.choices, default=UserStatus.PENDING)

    # Invitation
    invitation_token = models.CharField(max_length=255, blank=True, db_index=True)
    invitation_sent_at = models.DateTimeField(null=True, blank=True)
    invitation_accepted_at = models.DateTimeField(null=True, blank=True)
    invited_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='invited_users')

    # 2FA -TOTP (Google Authenticator)
    totp_secret = models.CharField(max_length=255, blank=True)
    totp_enabled = models.BooleanField(default=False)

    # 2FA - Email OTP
    email_otp_code = models.CharField(max_length=6, blank=True)
    email_otp_expires_at = models.DateTimeField(null=True, blank=True)

    # 2FA - SMS OTP
    sms_otp_code = models.CharField(max_length=6, blank=True)
    sms_otp_expires_at = models.DateTimeField(null=True, blank=True)

    # Permissions
    can_publish_prod = models.BooleanField(default=False)

    # Django required
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    last_login_at = models.DateTimeField(null=True, blank=True)

    # Détails supplémentaires requis pour le futur admin d'une organization
    functions = models.CharField(max_length=150, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        constraints = [
            models.UniqueConstraint(fields=["email"], name="user_email_unique"),
        ]

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"