from ninja_extra import api_controller, route
from ninja import File, Form
from ninja.files import UploadedFile
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from ninja_jwt.authentication import JWTAuth

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from src.organizations.models import Organization
from src.dids.models import Certificate
from src.dids.did_registry_api.schemas.envelopes import ok
from src.dids.proof_crypto_engine.certs.loaders import load_x509, compute_fingerprint
from src.dids.proof_crypto_engine.certs.jwk_normalize import jwk_from_public_key
from src.dids.proof_crypto_engine.certs.explicit_ec_fallback import (
    extract_ec_jwk_from_cert_der,
)


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

        # Ensure uploaded file pointer is reset before saving to FileField
        try:
            file.seek(0)
        except Exception:
            pass

        try:
            cert = load_x509(data, eff_fmt, password=password)
            fingerprint = compute_fingerprint(cert)

            # Try native path first (RSA / EC named curves)
            try:
                pub = cert.public_key()
                jwk = jwk_from_public_key(pub)

                # Build compliance meta for native path
                if isinstance(pub, rsa.RSAPublicKey):
                    compliance = {
                        "status": "OK",
                        "reason": None,
                        "ec_params_encoding": None,
                        "detected_curve": None,
                        "jose_crv": None,
                    }
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    name = getattr(pub.curve, "name", None)
                    jose_crv = jwk.get("crv")
                    if jose_crv in ("P-256", "P-384", "P-521"):
                        compliance = {
                        "status": "OK",
                        "reason": None,
                        "ec_params_encoding": "named",
                        "detected_curve": name,
                        "jose_crv": jose_crv,
                    }
                    else:
                    # Named curve but not a JOSE-registered one
                        compliance = {
                            "status": "NON_COMPLIANT",
                            "reason": "UNKNOWN_CURVE_NAMED",
                            "ec_params_encoding": "named",
                            "detected_curve": name,
                            "jose_crv": jose_crv,
                        }
                else:
                    # Other key types are unsupported in our platform
                    raise ValueError("Unsupported public key type")

            except Exception as e:
                # Known cryptography limitation (explicit EC params) → fallback
                try:
                    der = cert.public_bytes(Encoding.DER)
                    jwk, compliance = extract_ec_jwk_from_cert_der(der)
                except Exception:
                    # surface original cause if fallback also fails
                    raise e

        except HttpError:            
            # propagate earlier HttpError as-is
            raise
        except Exception as e:
            raise HttpError(400, f"Certificate parsing failed: {e}")

        # Persist certificate row (including compliance)
        cert_row = Certificate.objects.create(
            owner=request.user,
            organization=org,
            file=file,
            format=eff_fmt,
            extracted_jwk=jwk,
            fingerprint=fingerprint,
            compliance=compliance,
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
