from ninja_extra import api_controller, route
from ninja import File, Form
from ninja.files import UploadedFile
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from ninja_jwt.authentication import JWTAuth

from src.organizations.models import Organization
from src.dids.models import Certificate
from src.dids.did_registry_api.schemas.envelopes import ok
from src.dids.proof_crypto_engine.certs.loaders import load_x509, compute_fingerprint
from src.dids.proof_crypto_engine.certs.jwk_normalize import jwk_from_public_key


def _is_pem(data: bytes) -> bool:
    return b"-----BEGIN" in data and b"-----END" in data


def _detect_fmt(data: bytes) -> str:
    return "PEM" if _is_pem(data) else "DER"


@api_controller("/registry", tags=["DID Registry"], auth=JWTAuth())
class CertificatesController:
    @route.post("/certificates")
    def upload(
        self,
        request,
        organization_id: str = Form(...),
        format: str = Form(...),
        file: UploadedFile = File(...),
        password: str | None = Form(None),
    ):
        org = get_object_or_404(Organization, pk=organization_id)
        fmt = (format or "").upper()
        allowed = {"PEM", "DER", "PKCS7", "PKCS12", "CRT", "AUTO"}
        if fmt not in allowed:
            raise HttpError(
                400,
                "Unsupported certificate format. Use: PEM, DER, PKCS7, PKCS12, CRT, AUTO.",
            )
        data = file.read()
        eff_fmt = _detect_fmt(data) if fmt in {"CRT", "AUTO"} else fmt

        try:
            cert = load_x509(data, eff_fmt, password=password)
            jwk = jwk_from_public_key(cert.public_key())
            fingerprint = compute_fingerprint(cert)
        except Exception as e:
            raise HttpError(400, f"Certificate parsing failed: {e}")

        cert_row = Certificate.objects.create(
            owner=request.user,
            organization=org,
            file=file,
            format=eff_fmt,
            extracted_jwk=jwk,
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
            status=201,
        )
        