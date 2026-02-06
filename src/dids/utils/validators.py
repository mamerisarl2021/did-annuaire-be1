import jsonschema
import json

from importlib import resources
from enum import StrEnum


def validate_did_document(doc: dict):
    with (
        resources.files("src.dids.schemas")
        .joinpath("did_document.schema.json")
        .open("rb") as f
    ):
        schema = json.load(f)
    jsonschema.validate(instance=doc, schema=schema)

#-------------------CONSTANTS----------------------#

class DIDRegistrarState(StrEnum):
    FINISHED = "finished"
    ACTION = "action"
    UPDATE = "update"
    WAIT = "wait"
    ERROR = "error"