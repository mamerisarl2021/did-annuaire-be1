# Replaces broken 0007_alter_user_password_reset_token

from django.db import migrations, models


def empty_tokens_to_null(apps, schema_editor):
    """Convert empty-string password_reset_tokens to NULL so unique constraint works."""
    User = apps.get_model("users", "User")
    User.objects.filter(password_reset_token="").update(password_reset_token=None)


def null_tokens_to_empty(apps, schema_editor):
    """Reverse: NULL back to empty string."""
    User = apps.get_model("users", "User")
    User.objects.filter(password_reset_token__isnull=True).update(password_reset_token="")


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0006_add_password_reset_fields"),
    ]

    operations = [
        # 1. Make nullable first (no unique yet — safe even with duplicate empty strings)
        migrations.AlterField(
            model_name="user",
            name="password_reset_token",
            field=models.CharField(
                max_length=255,
                blank=True,
                null=True,
                db_index=True,
            ),
        ),
        # 2. Convert all "" to NULL
        migrations.RunPython(
            empty_tokens_to_null,
            null_tokens_to_empty,
        ),
        # 3. Now add unique (safe — NULLs are distinct in PostgreSQL)
        migrations.AlterField(
            model_name="user",
            name="password_reset_token",
            field=models.CharField(
                max_length=255,
                blank=True,
                null=True,
                default=None,
                db_index=True,
                unique=True,
            ),
        ),
    ]