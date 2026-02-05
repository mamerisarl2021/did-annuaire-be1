from __future__ import annotations
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12, Encoding


def _first_cert_from_pkcs7(data: bytes, is_pem: bool) -> x509.Certificate | None:
    try:
        certs: list[x509.Certificate] = (
            pkcs7.load_pem_pkcs7_certificates(data)
            if is_pem
            else pkcs7.load_der_pkcs7_certificates(data)
        )
        return certs[0] if certs else None
    except Exception:
        return None


def _is_explicit_params_error(e: Exception) -> bool:
    """Check if error is related to explicit EC parameters"""
    msg = str(e).lower()
    return any(
        keyword in msg
        for keyword in [
            "explicit",
            "parameter",
            "unnamed curve",
            "explicit curves are not supported",
            "explicit ec parameters",
            "ecdsa keys with explicit parameters",
        ]
    )


def load_x509(file_bytes: bytes, fmt: str, password: str | None = None) -> x509.Certificate:
    """
    Load X.509 certificate. May raise exception if explicit EC params are detected.
    Caller should handle this and use Java fallback if needed.
    """
    f = (fmt or "").upper()
    if f == "PEM":
        try:
            return x509.load_pem_x509_certificate(file_bytes)
        except Exception as e:
            # Check if it's explicit params before trying PKCS7
            if _is_explicit_params_error(e):
                raise
            c = _first_cert_from_pkcs7(file_bytes, is_pem=True)
            if c:
                return c
            raise
    if f == "DER":
        try:
            return x509.load_der_x509_certificate(file_bytes)
        except Exception as e:
            # Check if it's explicit params before trying PKCS7
            if _is_explicit_params_error(e):
                raise
            c = _first_cert_from_pkcs7(file_bytes, is_pem=False)
            if c:
                return c
            raise
    if f == "PKCS7":
        c = _first_cert_from_pkcs7(file_bytes, is_pem=(b"-----BEGIN" in file_bytes))
        if not c:
            raise ValueError("No certificate found in PKCS#7")
        return c
    if f == "PKCS12":
        key, cert, _extra = pkcs12.load_key_and_certificates(
            file_bytes, password.encode() if password else None
        )
        if cert is None:
            raise ValueError("No certificate found in PKCS#12")
        return cert
    raise ValueError(f"Unsupported certificate format: {fmt}")


def compute_fingerprint(cert: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint from certificate DER bytes"""
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest().upper()


def compute_fingerprint_from_der(der_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint directly from DER bytes (for Java fallback)"""
    return hashlib.sha256(der_bytes).hexdigest().upper()