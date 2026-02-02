from __future__ import annotations
from src.dids.models import DID, UploadedPublicKey


def latest_key_versions(did: DID) -> dict[str, UploadedPublicKey]:
    qs = UploadedPublicKey.objects.filter(did=did, is_active=True).order_by(
        "key_id", "-version"
    )
    out: dict[str, UploadedPublicKey] = {}
    for upk in qs:
        if upk.key_id not in out:
            out[upk.key_id] = upk
    return out


# TODO add jwks
def list_key_versions(did: DID) -> list[dict]:
    items: dict[str, list[UploadedPublicKey]] = {}
    for upk in UploadedPublicKey.objects.filter(did=did).order_by("key_id", "version"):
        items.setdefault(upk.key_id, []).append(upk)
    out: list[dict] = []
    for key_id, arr in items.items():
        versions = [u.version for u in arr]
        out.append(
            {
                "key_id": key_id,
                "versions": versions,
                "current": max(versions) if versions else 1,
                "purposes": arr[-1].purposes if arr else [],
                "public_jwk": arr[-1].public_key_jwk,
            }
        )
    return out
