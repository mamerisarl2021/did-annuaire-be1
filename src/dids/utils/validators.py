from importlib import resources
import jsonschema, json

def validate_did_document(doc: dict):
    with resources.files("src.dids.schemas").joinpath("did_document.schema.json").open("rb") as f:
        schema = json.load(f)
    jsonschema.validate(instance=doc, schema=schema)
