import os
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import IntegrityError


class Command(BaseCommand):
    help = "Create or update a superuser from environment variables"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force the creation of the admin user or update password if exists",
        )

    def handle(self, *args: Any, **options: Any):
        force = options.get("force", False)
        User = get_user_model()

        # Get credentials from environment
        admin_username = os.getenv("DJANGO_SUPERUSER_NAME")
        admin_password = os.getenv("DJANGO_SUPERUSER_PASSWORD")
        admin_email = os.getenv("DJANGO_SUPERUSER_EMAIL")

        # Validate all required fields
        if not admin_username:
            self.stderr.write(
                self.style.ERROR(
                    "DJANGO_SUPERUSER_NAME environment variable is required."
                )
            )
            return

        if not admin_email:
            self.stderr.write(
                self.style.ERROR(
                    "DJANGO_SUPERUSER_EMAIL environment variable is required."
                )
            )
            return

        if not admin_password:
            self.stderr.write(
                self.style.ERROR(
                    "DJANGO_SUPERUSER_PASSWORD environment variable is required."
                )
            )
            return

        # Check if User exists (by username or email)
        existing_user = User.objects.filter(username=admin_username).first()

        if existing_user and not force:
            self.stdout.write(
                self.style.WARNING(
                    f"Admin User '{admin_username}' already exists. Use --force to update password."
                )
            )
            return

        if existing_user and force:
            # Update existing User's password
            existing_user.set_password(admin_password)
            existing_user.email = admin_email  # Update email as well
            existing_user.is_superuser = True
            existing_user.is_staff = True
            existing_user.is_active = True
            existing_user.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully updated admin User '{admin_username}' with new password and email."
                )
            )
            return

        # Create new superuser
        try:
            User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully created admin User:\n"
                    f"  Username: {admin_username}\n"
                    f"  Email: {admin_email}"
                )
            )
        except IntegrityError as e:
            self.stderr.write(
                self.style.ERROR(
                    f"Failed to create admin User. A User with this username or email may already exist.\n"
                    f"Error: {str(e)}"
                )
            )
        except Exception as e:
            import traceback

            self.stderr.write(
                self.style.ERROR(f"Unexpected error creating admin User: {e!s}")
            )
            self.stderr.write(traceback.format_exc())
