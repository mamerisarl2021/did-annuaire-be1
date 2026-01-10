from types import SimpleNamespace as NS
from src.organizations.presenters import org_to_list_dto_admin, org_to_detail_dto_admin


def make_file(url=None, name=None):
    return NS(url=url, name=name)


def make_admin(**kw):
    defaults = dict(
        id="admin-uuid",
        email="admin@org.com",
        first_name="Admin",
        last_name="User",
        phone="+123",
        functions="IT Manager",
        status="PENDING",
    )
    defaults.update(kw)
    return NS(**defaults)


def make_org(list_admin=True, **kw):
    defaults = dict(
        id="org-uuid",
        name="Acme Corp",
        slug="acme-corp",
        type="ADMINISTRATION",
        country="CM",
        email="contact@acme.com",
        phone="+1",
        address="HQ",
        status="PENDING",
        allowed_email_domains=["acme.com"],
        max_users=10,
        max_applications=5,
        validated_at=None,
        refusal_reason="",
        created_at=NS(isoformat=lambda: "2026-01-08T10:00:00Z"),
        authorization_document=make_file(url="/media/auth.pdf", name="auth.pdf"),
        justification_document=make_file(url="/media/just.pdf", name="just.pdf"),
    )
    defaults.update(kw)
    org = NS(**defaults)
    # prefetch to_attr="admin_user" yields a list
    if list_admin:
        org.admin_user = [make_admin()]
    else:
        org.admin_user = []
    return org


def test_org_to_list_dto_with_admin_email():
    org = make_org()
    dto = org_to_list_dto_admin(org)
    assert dto["id"] == "org-uuid"
    assert dto["admin"] == "admin@org.com"


def test_org_to_list_dto_no_admin():
    org = make_org(list_admin=False)
    dto = org_to_list_dto_admin(org)
    assert dto["admin"] is None


def test_org_to_detail_dto_includes_documents_and_admin():
    org = make_org()
    dto = org_to_detail_dto_admin(org)
    assert dto["documents"]["authorization_document_url"] == "/media/auth.pdf"
    assert dto["documents"]["justification_document_name"] == "just.pdf"
    assert dto["admin"]["functions"] == "IT Manager"
