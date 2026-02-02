from __future__ import annotations
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def jwk_from_public_key(pub) -> dict:
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
        e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
        return {"kty": "RSA", "n": _b64u(n), "e": _b64u(e)}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        x = nums.x.to_bytes((nums.x.bit_length() + 7) // 8, "big")
        y = nums.y.to_bytes((nums.y.bit_length() + 7) // 8, "big")
        crv_map = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
        name = pub.curve.name
        return {
            "kty": "EC",
            "crv": crv_map.get(name, name),
            "x": _b64u(x),
            "y": _b64u(y),
        }
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}
    if isinstance(pub, x25519.X25519PublicKey):
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "X25519", "x": _b64u(raw)}
    raise ValueError("Unsupported public key type")


# TODO: add support for secp256k1
