import uuid

from django.shortcuts import get_object_or_404
from ninja import File, Form
from ninja.files import UploadedFile
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from src.organizations.models import Organization
from .models import Certificate
from src.dids.utils.crypto import jwk_from_certificate
from .schemas import CertificateOut


@api_controller("/registry", tags=["DID Registry"])
class CertificateController:
    @route.post("/certificates", response=CertificateOut)
    def upload_certificate(self, request,
                           organization_id: uuid.UUID = Form(...),
                           format: str = Form(...),
                           file: UploadedFile = File(...),
                           password: str | None = Form(None)):
        org = get_object_or_404(Organization, pk=organization_id)
        fmt = format.upper()
        if fmt not in {"PEM","DER","PKCS7","PKCS12"}:
            raise HttpError(400, "Unsupported certificate format")
        file_bytes = file.read()
        jwk, fingerprint = jwk_from_certificate(file_bytes, fmt, password=password)

        cert = Certificate.objects.create(
            owner=request.user, organization=org, file=file, format=fmt,
            extracted_jwk=jwk, fingerprint=fingerprint,
        )
        return CertificateOut(id=cert.id, format=fmt, fingerprint=fingerprint, extracted_jwk=jwk)
