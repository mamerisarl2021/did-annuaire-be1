
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q, Exists, OuterRef

from src.dids.models import DID, DIDDocument

class Command(BaseCommand):
    help = "Backfill DID.status based on current PROD active documents."

    def handle(self, *args, **kwargs):
        # Exists subqueries
        prod_active = DIDDocument.objects.filter(
            did_id=OuterRef("pk"), environment="PROD", is_active=True
        )
        prod_active_deactivated = DIDDocument.objects.filter(
            did_id=OuterRef("pk"),
            environment="PROD",
            is_active=True,
        ).extra(where=["(document->>'deactivated')::boolean = true"])

        total = 0
        with transaction.atomic():
            # DEACTIVATED where active PROD doc has deactivated:true
            qs_deact = DID.objects.annotate(
                has_deactivated=Exists(prod_active_deactivated)
            ).filter(has_deactivated=True).exclude(status=DID.DIDStatus.DEACTIVATED)
            n1 = qs_deact.update(status=DID.DIDStatus.DEACTIVATED)

            # ACTIVE where there is an active PROD doc (and not deactivated)
            qs_active = DID.objects.annotate(
                has_active=Exists(prod_active)
            ).filter(has_active=True).exclude(status__in=[DID.DIDStatus.ACTIVE, DID.DIDStatus.DEACTIVATED])
            n2 = qs_active.update(status=DID.DIDStatus.ACTIVE)

            # DRAFT where no active PROD document
            qs_draft = DID.objects.annotate(
                has_active=Exists(prod_active)
            ).filter(has_active=False).exclude(status=DID.DIDStatus.DRAFT)
            n3 = qs_draft.update(status=DID.DIDStatus.DRAFT)

            total = n1 + n2 + n3

        self.stdout.write(self.style.SUCCESS(f"Updated {total} DIDs (DEACTIVATED={n1}, ACTIVE={n2}, DRAFT={n3})"))