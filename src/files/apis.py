from django.shortcuts import get_object_or_404

from src.files.models import File
from src.files.services import (
    FileDirectUploadService,
    FileStandardUploadService,
)


# adapt to django ninja
class FileStandardUploadApi:
    pass


class FileDirectUploadStartApi:
    pass


class FileDirectUploadLocalApi:
    pass


class FileDirectUploadFinishApi:
    pass
