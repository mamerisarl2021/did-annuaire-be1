import base64
from dataclasses import dataclass

import hvac
from django.conf import settings
import base58

MB_PREFIX = "z"  # multibase base58btc prefix


@dataclass
class TransitKeyRef:
    mount: str
    name: str


def _client() -> hvac.Client:
    return hvac.Client(
        url=settings.OPENBAO_ADDR, token=settings.OPENBAO_TOKEN, timeout=10
    )


def key_ref_for(org_slug: str, app_slug: str) -> TransitKeyRef:
    mount = getattr(settings, "OPENBAO_TRANSIT_MOUNT", "transit")
    prefix = getattr(settings, "OPENBAO_KEY_PREFIX", "didkey")
    name = f"{prefix}_org-{org_slug}_app-{app_slug}"
    return TransitKeyRef(mount=mount, name=name)


def ensure_ed25519_key(ref: TransitKeyRef) -> None:
    c = _client()
    try:
        c.secrets.transit.read_key(name=ref.name, mount_point=ref.mount)
    except Exception:
        # create if not exists
        c.secrets.transit.create_key(
            name=ref.name,
            mount_point=ref.mount,
            type="ed25519",
            exportable=False,  # clé privée non exportable
        )


def public_key_multibase(ref: TransitKeyRef) -> str:
    c = _client()
    resp = c.secrets.transit.read_key(name=ref.name, mount_point=ref.mount)
    # Pour ed25519, OpenBao/Vault renvoie généralement data.keys.<version>.public_key (base64)
    keys = resp["data"]["keys"]
    latest = sorted(keys.keys(), key=lambda x: int(x))[-1]
    pub_b64 = keys[latest].get("public_key")
    if not pub_b64:
        raise RuntimeError("Public key not found on transit key")
    pub_raw = base64.b64decode(pub_b64)
    return MB_PREFIX + base58.b58encode(pub_raw).decode("utf-8")


def sign_ed25519(ref: TransitKeyRef, payload: bytes) -> bytes:
    """
    Appelle transit/sign, retourne la signature brute (sans le préfixe 'vault:v1:').
    """
    c = _client()
    b64 = base64.b64encode(payload).decode("utf-8")
    resp = c.secrets.transit.sign_data(
        name=ref.name,
        mount_point=ref.mount,
        hash_algorithm="sha2-256",  # requis par l’API, ignoré pour ed25519 (signature directe)
        input=b64,
    )
    sig = resp["data"]["signature"]  # ex: 'vault:v1:BASE64SIG'
    raw_b64 = sig.split(":")[-1]
    return base64.b64decode(raw_b64)


def signature_multibase(signature_raw: bytes) -> str:
    return MB_PREFIX + base58.b58encode(signature_raw).decode("utf-8")
