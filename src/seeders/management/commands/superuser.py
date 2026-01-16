# src/seeders/management/commands/superuser.py
import os
from getpass import getpass

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction


def _model_has_field(model, field_name: str) -> bool:
    return any(f.name == field_name for f in model._meta.get_fields())


class Command(BaseCommand):
    help = "Create or update a platform superuser (email-only custom user model)."

    def add_arguments(self, parser):
        parser.add_argument("--email", dest="email", help="Superuser email")
        parser.add_argument("--password", dest="password", help="Superuser password")
        parser.add_argument("--first-name", dest="first_name", default="Admin")
        parser.add_argument("--last-name", dest="last_name", default="User")

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()

        email = options.get("email") or os.getenv("ADMIN_USER_EMAIL")
        password = options.get("password") or os.getenv("ADMIN_USER_PASSWORD")
        first_name = options.get("first_name") or os.getenv(
            "ADMIN_USER_FIRST_NAME", "Super"
        )
        last_name = options.get("last_name") or os.getenv(
            "ADMIN_USER_LAST_NAME", "User"
        )

        if not email:
            raise CommandError("Provide --email or set ADMIN_USER_EMAIL.")

        # Optional interactive password prompt if not provided via args/env
        if not password:
            self.stdout.write(self.style.WARNING("No password provided."))
            password = getpass("Enter superuser password: ").strip()
            if not password:
                raise CommandError("Password is required.")

        # IMPORTANT: filter by email only (no 'username' on custom user)
        existing = User.objects.filter(email__iexact=email).first()

        # Helper to set optional fields only if the model has them
        def set_optional_fields(u):
            if _model_has_field(User, "first_name"):
                u.first_name = first_name
            if _model_has_field(User, "last_name"):
                u.last_name = last_name
            # If your model has 'role' & 'status', set them but only if they exist
            if _model_has_field(User, "role"):
                try:
                    # Align with your choices if applicable; otherwise skip silently
                    u.role = "SUPERUSER"
                except Exception:
                    pass
            if _model_has_field(User, "status"):
                try:
                    u.status = "ACTIVE"
                except Exception:
                    pass
            return u

        if existing:
            # Upgrade existing user to superuser/staff and update password
            existing.is_superuser = True
            existing.is_staff = True
            set_optional_fields(existing)
            existing.set_password(password)
            existing.save()
            self.stdout.write(
                self.style.SUCCESS(f"Updated existing superuser: {email}")
            )
        else:
            # Create a brand new superuser (email is USERNAME_FIELD)
            kwargs = dict(
                email=email,
                password=password,
                is_staff=True,
                is_superuser=True,
            )
            # Add optional fields if present
            if _model_has_field(User, "first_name"):
                kwargs["first_name"] = first_name
            if _model_has_field(User, "last_name"):
                kwargs["last_name"] = last_name
            if _model_has_field(User, "role"):
                kwargs["role"] = "SUPERUSER"
            if _model_has_field(User, "status"):
                kwargs["status"] = "ACTIVE"

            user = User.objects.create_superuser(**kwargs)
            self.stdout.write(self.style.SUCCESS(f"Created superuser: {user.email}"))
