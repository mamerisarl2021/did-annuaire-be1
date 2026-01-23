import json, hashlib

try:
    import rfc8785
except ImportError:
    rfc8785 = None

def dumps_bytes(document: dict) -> bytes:
    if rfc8785:
        out = rfc8785.dumps(document)
        return out if isinstance(out, (bytes, bytearray)) else out.encode("utf-8")
    return json.dumps(document, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
