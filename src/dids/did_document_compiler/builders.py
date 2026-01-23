from src.dids.services import build_did, derive_org_slug, derive_user_slug, latest_key_versions_for_did

# Standard relationships we allow
STANDARD_PURPOSES = {
    "authentication",  # Proving identity
    "assertionMethod",  # Making claims
    "keyAgreement",  # Establishing shared secrets
    "capabilityInvocation",  # Exercising rights
    "capabilityDelegation",  # Delegating rights
}

DEFAULT_PURPOSES = ["authentication", "assertionMethod"]

# Key-type → allowed relationships (project policy)
KEY_ALLOWED_PURPOSES = {
    "ED25519": {"authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"},
    "X25519": {"keyAgreement"},
    "P-256":  {"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"},
    "P-384":  {"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"},
    "P-521":  {"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"},
    "RSA":    {"authentication", "assertionMethod", "capabilityInvocation"},

}


def _detect_key_kind(jwk: dict) -> str:
    kty = jwk.get("kty"); crv = jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519": return "ED25519"
    if kty == "OKP" and crv == "X25519": return "X25519"
    if kty == "EC" and crv in {"P-256", "secp256r1"}: return "P-256"
    if kty == "EC" and crv in {"P-384", "secp384r1"}: return "P-384"
    if kty == "EC" and crv in {"P-521", "secp521r1"}: return "P-521"
    if kty == "RSA": return "RSA"
    raise ValueError("Unsupported JWK for DID Document policy")


def _validate_and_normalize_purposes(jwk: dict, purposes: list[str] | None) -> list[str]:
    # Empty/None → defaults
    p = (purposes or []) or DEFAULT_PURPOSES

    # 1) refuse unknown relationships (explicitly)
    unknown = [rel for rel in p if rel not in STANDARD_PURPOSES]
    if unknown:
        raise ValueError(f"Invalid purpose(s): {', '.join(unknown)}")

    # 2) enforce key-type → allowed relationships
    kind = _detect_key_kind(jwk)
    allowed = KEY_ALLOWED_PURPOSES[kind]
    not_allowed = [rel for rel in p if rel not in allowed]
    if not_allowed:
        raise ValueError(
            f"Purpose(s) not allowed for key type {kind}: {', '.join(not_allowed)}"
        )
    return p


def _choose_alg_from_jwk(jwk: dict, purposes: list[str]) -> str | None:
    kty = jwk.get("kty"); crv = jwk.get("crv")
    if kty == "RSA":
        return "RS256"
    if kty == "EC":
        if "keyAgreement" in purposes:
            return None  # pas d’hypothèse (ECDH-ES) → on omet
        if crv in (None, "P-256", "secp256r1"):
            return "ES256"
        if crv in ("P-384", "secp384r1"):
            return "ES384"
        if crv in ("P-521", "secp521r1"):
            return "ES512"
        return None
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    # X25519: agreement-only → aucun alg JWS
    return None



def _decide_use_key_ops(purposes: list[str]):
    has_ka = "keyAgreement" in purposes
    has_sig = any(
        p in purposes for p in ("authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"))
    if has_ka and has_sig:  # ambiguous → omit as requested
        return None, None
    if has_ka:  # agreement only
        return "enc", ["deriveKey"]
    return "sig", ["verify"]  # signature-only


def build_did_document_with_keys(
        organization,
        owner,
        document_type: str,
        keys: list[dict],  # each: {"jwk": dict, "key_id": str, "purposes": Optional[List[str]]}
        services: list[dict] | None = None,
) -> tuple[str, dict]:
    org_slug = derive_org_slug(organization)
    user_slug = derive_user_slug(owner)
    did = build_did(org_slug, user_slug, document_type)

    # Start in preferred order
    doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "controller": did,
        "verificationMethod": [],
    }

    # Prepare relationships in desired visual order; fill later
    rel_names = ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"]
    for rel in rel_names:
        pass  # init lazily to keep doc compact

    # Build each VM and map relationships
    rel_index: dict[str, list[str]] = {r: [] for r in rel_names}
    for entry in keys:
        jwk = dict(entry["jwk"])
        key_id = entry["key_id"]
        purposes = entry.get("purposes")
        p = _validate_and_normalize_purposes(jwk, purposes)

        vm_id = f"{did}#{key_id}"

        # JWK extensions (kid, alg; use/key_ops only when unambiguous)
        jwk.setdefault("kid", vm_id)
        alg = _choose_alg_from_jwk(jwk, p)
        if alg:
            jwk.setdefault("alg", alg)
        use, key_ops = _decide_use_key_ops(p)
        if use is not None and key_ops is not None:
            jwk.setdefault("use", use)
            jwk.setdefault("key_ops", key_ops)

        doc["verificationMethod"].append({
            "id": vm_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk,
        })

        for rel in p:
            rel_index[rel].append(vm_id)

    # Attach relationships in the preferred order if non-empty
    for rel in rel_names:
        if rel_index[rel]:
            doc[rel] = rel_index[rel]

    if services:
        doc["service"] = services

    return did, doc


def build_did_and_document(organization, owner, document_type: str,
                           jwk: dict, key_id: str = "key-1",
                           purposes: list[str] | None = None,
                           services: list[dict] | None = None) -> tuple[str, dict]:
    return build_did_document_with_keys(
        organization, owner, document_type,
        keys=[{"jwk": jwk, "key_id": key_id, "purposes": purposes}],
        services=services,
    )


def build_did_document_from_db(did_obj) -> tuple[str, dict, dict[str, int]]:
    """
    Compose a DID Document from current active key versions stored in DB for this DID.
    Returns (did, document, key_versions_map).
    """
    latest = latest_key_versions_for_did(did_obj)
    keys_input = []
    versions_map: dict[str, int] = {}
    for key_id, upk in latest.items():
        versions_map[key_id] = upk.version
        keys_input.append({
            "jwk": upk.public_key_jwk_snapshot or upk.public_key_jwk,
            "key_id": key_id,
            "purposes": upk.purposes,
        })
    did, doc = build_did_document_with_keys(
        organization=did_obj.organization,
        owner=did_obj.owner,
        document_type=did_obj.document_type,
        keys=keys_input,
        services=None,
    )
    return did, doc, versions_map
