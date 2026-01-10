from django.contrib import admin

from src.files.models import File
from src.files.services import FileStandardUploadService


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "original_file_name",
        "file_name",
        "file_type",
        "upload_finished_at",
        "created_at",
    )

    def has_add_permission(self, request):
        return False
