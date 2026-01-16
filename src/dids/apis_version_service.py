# Endpoints: didrecords, methods, diddocuments, didversions, count.
from datetime import datetime, timezone
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.db.models import Q
from ninja_extra import api_controller, route
from .models import DID, DIDDocument
from .schemas import DidRecord, DidDocument1, DidState1, DidVersion


def to_epoch_ms(dt: datetime | None) -> int | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


@api_controller("/version-service", tags=["Version Service"])
class VersionServiceController:

    @route.get("/didrecords")
    def get_did_records(
        self, request,
        did: str | None = None,
        method: str | None = None,
        versionTime: int | None = None,
        versionTimeFrom: int | None = None,
        versionTimeTo: int | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[DidRecord]:
        qs = DIDDocument.objects.select_related("did").all()

        if did:
            qs = qs.filter(did__did=did)
        if method:
            qs = qs.filter(did__method=method)
        # versionTime filters on published_at else created_at
        if versionTime:
            ts = datetime.fromtimestamp(versionTime/1000.0, tz=timezone.utc)
            qs = qs.filter(Q(published_at__lte=ts) | (Q(published_at__isnull=True) & Q(created_at__lte=ts)))
        if versionTimeFrom and versionTimeTo:
            f = datetime.fromtimestamp(versionTimeFrom/1000.0, tz=timezone.utc)
            t = datetime.fromtimestamp(versionTimeTo/1000.0, tz=timezone.utc)
            qs = qs.filter(
                Q(published_at__range=(f,t)) |
                (Q(published_at__isnull=True) & Q(created_at__range=(f,t)))
            )

        qs = qs.order_by("-created_at")[offset: offset + min(limit, 200)]
        out: list[DidRecord] = []
        for doc in qs:
            when = doc.published_at or doc.created_at
            out.append(DidRecord(
                id=str(doc.pk),
                timestamp=to_epoch_ms(when),
                did=doc.did.did,
                method=doc.did.method,
                didDocument=DidDocument1(
                    didRecordId=str(doc.pk),
                    did=doc.did.did,
                    documentContent=doc.document,
                    documentMetadata={"environment": doc.environment, "version": doc.version},
                ),
                didVersion=DidVersion(
                    didRecordId=str(doc.pk),
                    did=doc.did.did,
                    versionId=str(doc.version),
                    versionTime=to_epoch_ms(when),
                    versionMetadata={"is_active": doc.is_active},
                ),
                didState=DidState1(
                    didRecordId=str(doc.pk),
                    did=doc.did.did,
                    state=doc.did.status,
                    stateTime=to_epoch_ms(when),
                    stateMetadata={"published_relpath": doc.published_relpath},
                ),
            ))
        return out

    @route.get("/didrecords/methods")
    def methods(self, request) -> list[str]:
        return ["web"]

    @route.get("/didrecords/count")
    def count_by_method(self, request, method: str | None = None) -> int:
        qs = DID.objects.all()
        if method:
            qs = qs.filter(method=method)
        return qs.count()

    @route.get("/diddocuments")
    def get_did_documents(
        self, request,
        did: str | None = None,
        method: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[DidDocument1]:
        qs = DIDDocument.objects.select_related("did").all()
        if did:
            qs = qs.filter(did__did=did)
        if method:
            qs = qs.filter(did__method=method)
        qs = qs.order_by("-created_at")[offset: offset + min(limit, 200)]
        return [
            DidDocument1(
                didRecordId=str(doc.pk),
                did=doc.did.did,
                documentContent=doc.document,
                documentMetadata={"environment": doc.environment, "version": doc.version},
            )
            for doc in qs
        ]

    @route.get("/didversions")
    def get_did_versions(
        self, request,
        did: str | None = None,
        method: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[DidVersion]:
        qs = DIDDocument.objects.select_related("did").all()
        if did:
            qs = qs.filter(did__did=did)
        if method:
            qs = qs.filter(did__method=method)
        qs = qs.order_by("-created_at")[offset: offset + min(limit, 200)]
        out: list[DidVersion] = []
        for doc in qs:
            when = doc.published_at or doc.created_at
            out.append(DidVersion(
                didRecordId=str(doc.pk),
                did=doc.did.did,
                versionId=str(doc.version),
                versionTime=to_epoch_ms(when),
                versionMetadata={"environment": doc.environment, "is_active": doc.is_active},
            ))
        return out
