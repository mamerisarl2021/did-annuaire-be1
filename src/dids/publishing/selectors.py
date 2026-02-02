from src.dids.resolver.services import parse_did_web
from src.dids.publishing.paths import build_relpath


def published_dir_relpath_for_did(did: str) -> tuple[str, str, str, str]:
    """
    Compute the published directory (relative to DIDS_ROOT) for this DID.
    Returns (rel_dir, org, user, doc_type).
    Example rel_dir: "org-slug/user-slug/doc_type"
    """
    host, org, user, doc_type = parse_did_web(did)
    rel_json = build_relpath(org, user, doc_type)  # "{org}/{user}/{doc_type}/did.json"
    rel_dir = rel_json.rsplit("/", 1)[0]
    return rel_dir, org, user, doc_type


def relpaths_for_did(did: str) -> dict[str, str]:
    """
    Compute relative paths (under DIDS_ROOT) for doc_type, user, and org scopes.
    Returns: {"doc_type": "...", "user": "...", "org": "...", "org_slug": org, "user_slug": user, "doc_type_slug": doc_type}
    """
    host, org, user, doc_type = parse_did_web(did)
    # doc_type dir
    rel_json = build_relpath(org, user, doc_type)  # "{org}/{user}/{doc_type}/did.json"
    doc_type_rel = rel_json.rsplit("/", 1)[0]
    # user dir
    user_rel = f"{org}/{user}"
    # org dir
    org_rel = f"{org}"
    return {
        "doc_type": doc_type_rel,
        "user": user_rel,
        "org": org_rel,
        "org_slug": org,
        "user_slug": user,
        "doc_type_slug": doc_type,
    }
