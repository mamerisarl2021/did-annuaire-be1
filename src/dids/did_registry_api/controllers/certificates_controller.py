from ninja_extra import api_controller, route
from ninja import File, Form
from ninja.files import UploadedFile
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from ninja_jwt.authentication import JWTAuth

from src.dids import services, selectors
from src.organizations.models import Organization
from src.dids.did_registry_api.schemas.envelopes import ok, err


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class CertificatesController:
    @route.post("/certificates/preview")
    def preview(
            self,
            request,
            organization_id: str = Form(...),
            format: str = Form(...),
            file: UploadedFile = File(...),
            password: str | None = Form(None),
    ):
        """
        Validates and normalizes the certificate, returns JWK + fingerprint without persisting.
        """
        org = get_object_or_404(Organization, pk=organization_id)

        fmt = (format or "").upper()
        allowed = {"PEM", "DER", "PKCS7", "PKCS12", "CRT", "AUTO"}
        if fmt not in allowed:
            return err(request, 400, "UNSUPPORTED_CERT_FORMAT", path="/api/registry/certificates/preview")

        data = file.read()
        eff_fmt = services.detect_effective_format(fmt, data)

        try:
            jwk, fingerprint = services.parse_and_normalize_certificate(file_bytes=data, fmt=eff_fmt, password=password)
        except Exception as e:
            raise HttpError(400, f"Certificate parsing failed: {e}")

        return ok(
            request,
            did_state={"state": "action"},
            did_doc_meta={"public_jwk": jwk, "fingerprint": fingerprint},
            did_reg_meta={"method": "web"},
            status=200,
        )

    @route.post("/certificates")
    def upload(
            self,
            request,
            organization_id: str = Form(...),
            format: str = Form(...),
            file: UploadedFile = File(...),
            password: str | None = Form(None),
    ):
        """
        Idempotent by (organization, fingerprint):
        - If a cert with same fingerprint already exists in this org → return it (200).
        - If exists in another org → 409 CERT_FINGERPRINT_TAKEN_BY_ANOTHER_ORG.
        - Else create and return 201.
        """
        org = get_object_or_404(Organization, pk=organization_id)

        fmt = (format or "").upper()
        allowed = {"PEM", "DER", "PKCS7", "PKCS12", "CRT", "AUTO"}
        if fmt not in allowed:
            return err(request, 400, "UNSUPPORTED_CERT_FORMAT", path="/api/registry/certificates")

        data = file.read()
        eff_fmt = services.detect_effective_format(fmt, data)

        try:
            jwk, fingerprint = services.parse_and_normalize_certificate(file_bytes=data, fmt=eff_fmt, password=password)
        except Exception as e:
            raise HttpError(400, f"Certificate parsing failed: {e}")

        # Cross-org collision → fail fast (Certificate.fingerprint is globally unique)
        if selectors.cert_exists_in_other_org(fingerprint=fingerprint, organization_id=org.id):
            return err(
                request,
                409,
                "CERT_FINGERPRINT_TAKEN_BY_ANOTHER_ORG",
                path="/api/registry/certificates",
                extra={"fingerprint": fingerprint},
            )

        # Rewind uploaded file pointer before saving to FileField
        try:
            file.seek(0)
        except Exception:
            pass

        cert_row, created = services.upsert_certificate(
            owner=request.user,
            organization=org,
            file_obj=file,
            fmt=eff_fmt,
            jwk=jwk,
            fingerprint=fingerprint,
        )

        return ok(
            request,
            did_state={"state": "action"},
            did_doc_meta={
                "certificate_id": str(cert_row.id),
                "public_jwk": cert_row.extracted_jwk,
                "fingerprint": fingerprint,
            },
            did_reg_meta={"method": "web"},
            status=201 if created else 200,
        )