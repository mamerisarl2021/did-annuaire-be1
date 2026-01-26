import os
import tempfile
import pathlib

from django.conf import settings

from src.dids.proof_crypto_engine.canonical.jcs import sha256_hex

DIDS_ROOT = settings.DIDS_ROOT

def atomic_write(relpath: str, data: bytes) -> tuple[str, str | None]:
    path = pathlib.Path(DIDS_ROOT) / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as tmp:
        tmp.write(data); tmp.flush(); os.fsync(tmp.fileno())
        name = tmp.name
    os.replace(name, str(path))
    return sha256_hex(data), None
