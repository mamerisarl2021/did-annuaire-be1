from __future__ import annotations

import mimetypes
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from src.files.enums import FileUploadStorage
from src.files.models import File
from src.files.utils import (
    bytes_to_mib,
    file_generate_local_upload_url,
    file_generate_name,
    file_generate_upload_path,
)
from src.users.models import User


def _validate_file_size(file_obj: Any) -> None:
    max_size = settings.FILE_MAX_SIZE
    if hasattr(file_obj, "size") and file_obj.size > max_size:
        raise ValidationError(
            f"File is too large. It should not exceed {bytes_to_mib(max_size)} MiB"
        )


class FileStandardUploadService:
    """
    Encapsulates classic (non-direct) uploads: create & update.
    """

    def __init__(self, user: User, file_obj: Any):
        self.user = user
        self.file_obj = file_obj

    def _infer_file_name_and_type(self, file_name: str = "", file_type: str = "") -> tuple[str, str]:
        if not file_name:
            file_name = getattr(self.file_obj, "name", "") or "upload.bin"

        if not file_type:
            guessed, _enc = mimetypes.guess_type(file_name)
            file_type = "" if guessed is None else guessed

        return file_name, file_type

    @transaction.atomic
    def create(self, file_name: str = "", file_type: str = "") -> File:
        _validate_file_size(self.file_obj)

        file_name, file_type = self._infer_file_name_and_type(file_name, file_type)

        obj = File(
            file=self.file_obj,
            original_file_name=file_name,
            file_name=file_generate_name(file_name),
            file_type=file_type,
            uploaded_by=self.user,
            upload_finished_at=timezone.now(),
        )
        obj.full_clean()
        obj.save()
        return obj

    @transaction.atomic
    def update(self, file: File, file_name: str = "", file_type: str = "") -> File:
        _validate_file_size(self.file_obj)

        file_name, file_type = self._infer_file_name_and_type(file_name, file_type)

        file.file = self.file_obj
        file.original_file_name = file_name
        file.file_name = file_generate_name(file_name)
        file.file_type = file_type
        file.upload_finished_at = timezone.now()

        file.full_clean()
        file.save()
        return file


class FileDirectUploadService:
    """
    Direct upload flow:
    - start(): creates DB record and returns upload target (S3 presigned POST or local URL)
    - finish(): marks upload as completed
    - upload_local(): helper when using local direct upload endpoint
    """

    def __init__(self, user: User):
        self.user = user

    @transaction.atomic
    def start(self, *, file_name: str, file_type: str) -> dict[str, Any]:
        file = File(
            original_file_name=file_name,
            file_name=file_generate_name(file_name),
            file_type=file_type,
            uploaded_by=self.user,
            file=None,
        )
        file.full_clean()
        file.save()

        upload_path = file_generate_upload_path(file, file.file_name)

        # Prepare FileField object pointing to the final path
        file.file = file.file.field.attr_class(file, file.file.field, upload_path)
        file.save()

        if settings.FILE_UPLOAD_STORAGE == FileUploadStorage.S3:
            # Lazy import so local/dev without integrations won't break
            from src.integrations.aws.client import s3_generate_presigned_post  # type: ignore

            presigned = s3_generate_presigned_post(
                file_path=upload_path,
                file_type=file.file_type,
            )
            return {
                "id": file.id,
                **presigned,
            }

        # Local direct upload URL
        return {
            "id": file.id,
            "url": file_generate_local_upload_url(file_id=str(file.id)),
        }

    @transaction.atomic
    def finish(self, *, file: File) -> File:
        file.upload_finished_at = timezone.now()
        file.full_clean()
        file.save()
        return file

    @transaction.atomic
    def upload_local(self, *, file: File, file_obj: Any) -> File:
        _validate_file_size(file_obj)
        file.file = file_obj
        file.full_clean()
        file.save()
        return file
