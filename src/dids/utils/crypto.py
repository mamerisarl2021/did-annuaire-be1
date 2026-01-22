import base64
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _int_to_b64u(n: int) -> str:
    # big-endian, minimal length
    l = (n.bit_length() + 7) // 8 or 1
    return _b64u(n.to_bytes(l, "big"))


def _jwk_from_pubkey(pub) -> dict:
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {"kty": "RSA", "n": _int_to_b64u(nums.n), "e": _int_to_b64u(nums.e)}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        x = nums.x.to_bytes((nums.x.bit_length() + 7) // 8, "big")
        y = nums.y.to_bytes((nums.y.bit_length() + 7) // 8, "big")
        crv_map = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
            "secp256k1": "secp256k1",
        }
        name = pub.curve.name
        return {
            "kty": "EC",
            "crv": crv_map.get(name, name),
            "x": _b64u(x),
            "y": _b64u(y),
        }
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64u(pub.public_bytes(Encoding.Raw, serialization.PublicFormat.Raw)),
        }
    if isinstance(pub, x25519.X25519PublicKey):
        return {
            "kty": "OKP",
            "crv": "X25519",
            "x": _b64u(pub.public_bytes(Encoding.Raw, serialization.PublicFormat.Raw)),
        }
    raise ValueError("Unsupported public key type")


def _first_cert_from_pkcs7(pem_or_der: bytes, is_pem: bool) -> x509.Certificate | None:
    certs: list[x509.Certificate] = []
    try:
        if is_pem:
            certs = pkcs7.load_pem_pkcs7_certificates(pem_or_der)
        else:
            certs = pkcs7.load_der_pkcs7_certificates(pem_or_der)
    except Exception:
        pass
    return certs[0] if certs else None


def _load_x509_from_data(
    data: bytes, fmt: str, password: bytes | None
) -> x509.Certificate:
    fmt = fmt.upper()
    if fmt == "PEM":
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            # could be PEM PKCS7
            c = _first_cert_from_pkcs7(data, is_pem=True)
            if c:
                return c
            raise
    if fmt == "DER":
        try:
            return x509.load_der_x509_certificate(data)
        except Exception:
            # could be DER PKCS7
            c = _first_cert_from_pkcs7(data, is_pem=False)
            if c:
                return c
            raise
    if fmt == "PKCS7":
        c = _first_cert_from_pkcs7(data, is_pem=(b"-----BEGIN" in data))
        if not c:
            raise ValueError("No certificate found in PKCS#7")
        return c
    if fmt == "PKCS12":
        key, cert, _extra = pkcs12.load_key_and_certificates(data, password)
        if cert is None:
            raise ValueError("No certificate found in PKCS#12")
        return cert
    raise ValueError("Unsupported certificate format")


def compute_fingerprint(cert: x509.Certificate) -> str:
    # SHA-256 of DER encoding
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def jwk_from_certificate(
    file_bytes: bytes, fmt: str, password: str | None = None
) -> tuple[dict, str]:
    cert = _load_x509_from_data(
        file_bytes, fmt, password.encode() if password else None
    )
    pub = cert.public_key()
    jwk = _jwk_from_pubkey(pub)
    fp = compute_fingerprint(cert)
    return jwk, fp
