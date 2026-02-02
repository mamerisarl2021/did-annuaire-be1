ALLOWED_ALGS = {"RS256", "ES256", "ES384", "ES512", "EdDSA"}


def choose_alg_from_jwk(jwk: dict, purposes: list[str]) -> str | None:
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty == "RSA":
        return "RS256"
    if kty == "EC":
        if "keyAgreement" in purposes:
            return None
        if crv in (None, "P-256", "secp256r1"):
            return "ES256"
        if crv in ("P-384", "secp384r1"):
            return "ES384"
        if crv in ("P-521", "secp521r1"):
            return "ES512"
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    return None
