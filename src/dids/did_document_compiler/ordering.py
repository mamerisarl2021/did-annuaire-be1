from collections import OrderedDict

PREFERRED_ORDER = [
    "@context",
    "id",
    "controller",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
    "service",
    "proof",
    "deactivated",
]


def order_did_document(doc: dict) -> dict:
    out = OrderedDict()
    for k in PREFERRED_ORDER:
        if k in doc:
            out[k] = doc[k]
    for k, v in doc.items():
        if k not in out:
            out[k] = v
    return out
