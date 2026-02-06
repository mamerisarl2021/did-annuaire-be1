import os


def build_host() -> str:
    return os.environ.get("DID_DOMAIN_HOST", "annuairedid-fe.qcdigitalhub.com")


def build_relpath(org_slug: str, user_slug: str, doc_type: str) -> str:
    return f"{org_slug}/{user_slug}/{doc_type}/did.json"
