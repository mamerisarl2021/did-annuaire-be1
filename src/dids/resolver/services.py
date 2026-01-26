from __future__ import annotations
import json
import pathlib
from django.conf import settings
from django.shortcuts import get_object_or_404
from src.dids.models import DID as DIDModel

DIDS_ROOT = settings.DIDS_ROOT

def parse_did_web(did: str) -> tuple[str, str, str, str]:
    # did:web:{host}:{org}:{user}:{doc_type}
    if not did.startswith("did:web:"):
        raise ValueError("Unsupported DID method")
    parts = did.split(":")
    if len(parts) < 6:
        raise ValueError("Invalid did:web identifier")
    _, _, host, org, user, doc_type = parts[:6]
    return host, org, user, doc_type

def relpath_for(did: str) -> str:
    host, org, user, doc_type = parse_did_web(did)
    return f"{org}/{user}/{doc_type}/did.json"

def load_from_fs(did: str) -> dict:
    path = pathlib.Path(DIDS_ROOT) / relpath_for(did)
    with path.open("rb") as f:
        return json.loads(f.read().decode("utf-8"))

def load_from_db(did: str) -> dict | None:
    did_row = get_object_or_404(DIDModel, did=did)
    doc = did_row.documents.filter(environment="PROD", is_active=True).order_by("-version").first()
    return doc.document if doc else None

