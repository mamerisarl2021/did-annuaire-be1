from __future__ import annotations
import json, os, pathlib
from jsonschema import Draft7Validator

_DEFAULT_SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schemas" / "did-document.schema.json"
_SCHEMA = None

def load_schema() -> dict:
    override = os.environ.get("DID_DOCUMENT_SCHEMA_PATH")
    p = pathlib.Path(override) if override else _DEFAULT_SCHEMA_PATH
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_did_document(document: dict) -> None:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = load_schema()
    Draft7Validator(_SCHEMA).validate(document)
