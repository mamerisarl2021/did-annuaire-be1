def did_to_list_dto(doc) -> dict:
    return {
        "id": doc.id,
        "did": doc.did,
        "status": doc.status,
        "application": getattr(getattr(doc, "application", None), "name", None),
        "version": getattr(doc, "version", None),
        "created_at": doc.created_at.isoformat(),
        "preprod_published_at": doc.preprod_published_at.isoformat()
        if getattr(doc, "preprod_published_at", None)
        else None,
        "prod_published_at": doc.prod_published_at.isoformat()
        if getattr(doc, "prod_published_at", None)
        else None,
    }


def did_to_detail_dto(doc) -> dict:
    return {
        "id": doc.id,
        "did": doc.did,
        "status": doc.status,
        "version": getattr(doc, "version", None),
        "domain": getattr(doc, "domain", None),
        "document": getattr(doc, "document", None),
        "application": {
            "id": doc.application.id if getattr(doc, "application", None) else None,
            "name": doc.application.name if getattr(doc, "application", None) else None,
        },
        "created_at": doc.created_at.isoformat(),
        "validated_at": doc.validated_at.isoformat()
        if getattr(doc, "validated_at", None)
        else None,
        "prod_published_at": doc.prod_published_at.isoformat()
        if getattr(doc, "prod_published_at", None)
        else None,
    }
