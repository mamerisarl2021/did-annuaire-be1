import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _pubkey_from_jwk(jwk: dict):
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64u_decode(jwk["e"]), "big")
        pub_numbers = rsa.RSAPublicNumbers(e, n)
        return pub_numbers.public_key()
    if kty == "EC":
        x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
        crv = jwk.get("crv")
        curve = {
            "P-256": ec.SECP256R1(),
            "secp256r1": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "secp384r1": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
            "secp521r1": ec.SECP521R1(),
        }.get(crv)
        if not curve:
            raise ValueError("Unsupported EC curve")
        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return pub_numbers.public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"]))
    raise ValueError("Unsupported JWK")


def _encode_ecdsa_der(r: int, s: int) -> bytes:
    # Minimal DER encoder for ECDSA (SEQUENCE { r INTEGER, s INTEGER })
    def int_to_bytes(i: int) -> bytes:
        b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
        return b if b[0] & 0x80 == 0 else b"\x00" + b

    rb = int_to_bytes(r)
    sb = int_to_bytes(s)
    seq = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(seq)]) + seq


def verify_detached_jws(
    protected_b64: str, signature_b64: str, payload_str: str, jwk: dict
) -> bool:
    try:
        protected = json.loads(_b64u_decode(protected_b64).decode("utf-8"))
    except Exception:
        return False
    if protected.get("b64") is not False or "b64" not in protected.get("crit", []):
        return False
    alg = protected.get("alg")
    kid = protected.get("kid")
    if not alg or not kid:
        return False

    signing_input = (protected_b64 + "." + payload_str).encode("utf-8")
    sig = _b64u_decode(signature_b64)
    pub = _pubkey_from_jwk(jwk)

    try:
        if alg == "RS256":
            assert isinstance(pub, rsa.RSAPublicKey)
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True
        if alg in ("ES256", "ES384", "ES512"):
            assert isinstance(pub, ec.EllipticCurvePublicKey)
            half = len(sig) // 2
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            der = _encode_ecdsa_der(r, s)
            hash_alg = {
                "ES256": hashes.SHA256(),
                "ES384": hashes.SHA384(),
                "ES512": hashes.SHA512(),
            }[alg]
            pub.verify(der, signing_input, ec.ECDSA(hash_alg))
            return True
        if alg == "EdDSA":
            assert isinstance(pub, ed25519.Ed25519PublicKey)
            pub.verify(sig, signing_input)
            return True
        return False
    except Exception:
        return False
