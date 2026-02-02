import json, base64, os
from src.dids.proof_crypto_engine.canonical.jcs import dumps_bytes


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def prepare_signing_request(
    document: dict, kid: str, alg: str, nonce: str | None = None
) -> dict[str, str]:
    """
    Build a detached JWS (b64=false) signing request for JsonWebSignature2020.
    Returns: {protected, payload, signingInput, alg, kid, nonce}
    """
    if not nonce:
        nonce = _b64u(os.urandom(16))
    header = {"alg": alg, "kid": kid, "b64": False, "crit": ["b64"], "nonce": nonce}
    protected_b64 = _b64u(
        json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    payload = dumps_bytes(document).decode("utf-8")  # raw UTF-8 string (not base64)
    signing_input = f"{protected_b64}.{payload}"
    return {
        "protected": protected_b64,
        "payload": payload,
        "signingInput": signing_input,
        "alg": alg,
        "kid": kid,
        "nonce": nonce,
    }
