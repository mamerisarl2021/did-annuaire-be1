from datetime import datetime, timezone
from typing import Dict

from django.conf import settings
from pyld import jsonld

from src.crypto.openbao_transit import (
    key_ref_for,
    ensure_ed25519_key,
    public_key_multibase,
    sign_ed25519,
    signature_multibase,
)

SECURITY_CONTEXTS = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",  # pour Ed25519VerificationKey2020
]


def build_did(org_slug: str, user_slug: str, app_slug: str) -> str:
    host = "annuairedid-fe.qcdigitalhub.com"
    return f"did:web:{host}:{org_slug}:{user_slug}:{app_slug}"


def build_unsigned_did_document(org_slug: str, user_slug: str, app_slug: str) -> Dict:
    did = build_did(org_slug, user_slug, app_slug)
    ref = key_ref_for(org_slug, app_slug)
    ensure_ed25519_key(ref)
    pub_mb = public_key_multibase(ref)
    vm_id = f"{did}#keys-1"
    return {
        "@context": SECURITY_CONTEXTS,
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": pub_mb,
            }
        ],
        "assertionMethod": [vm_id],
    }


def sign_did_document(doc: Dict, org_slug: str, app_slug: str) -> Dict:
    """
    Ajoute un proof Data Integrity (eddsa-2022) en signant
    l’instance JSON-LD canonisée (URDNA2015).
    """
    # 1) Canonicalisation JSON-LD (URDNA2015) sans le champ 'proof'
    doc_no_proof = {k: v for k, v in doc.items() if k != "proof"}
    normalized = jsonld.normalize(
        doc_no_proof, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )
    payload = normalized.encode("utf-8")

    # 2) Signature via OpenBao/Transit
    ref = key_ref_for(org_slug, app_slug)
    sig_raw = sign_ed25519(ref, payload)
    sig_mb = signature_multibase(sig_raw)

    # 3) Proof Data Integrity (eddsa-2022)
    did = doc["id"]
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-2022",
        "created": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "verificationMethod": f"{did}#keys-1",
        "proofPurpose": "assertionMethod",
        "proofValue": sig_mb,
    }
    doc_signed = dict(doc)
    doc_signed["proof"] = proof
    return doc_signed
