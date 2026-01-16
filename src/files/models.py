from django.core.files.base import File as DjangoFile
from django.db import models

from src.common.models import BaseModel
from src.files.enums import FileUploadStorage
from src.files.utils import file_generate_upload_path
from src.users.models import User


class File(BaseModel):
    file = models.FileField(upload_to=file_generate_upload_path, blank=True, null=True)

    original_file_name = models.TextField()

    file_name = models.CharField(max_length=255, unique=True)
    file_type = models.CharField(max_length=255)

    upload_finished_at = models.DateTimeField(blank=True, null=True)

    uploaded_by = models.ForeignKey(User,
                                    on_delete=models.SET_NULL,
                                    null=True,
                                    related_name='uploaded_files'
                                    )

    @property
    def is_valid(self) -> bool:
        return bool(self.upload_finished_at)

    @property
    def url(self) -> str:
        if self.file:
            return self.file.url

        return ""

    def __str__(self) -> str:
        return f"{self.file_name} ({self.file_type})"
