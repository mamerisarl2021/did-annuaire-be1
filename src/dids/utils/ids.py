from __future__ import annotations
from uuid import uuid4


def generate_key_id() -> str:
    """
    Backend-owned stable key identifier.
    Format: key-(8 hex chars).
    """
    return f"key-{uuid4().hex[:8]}"
