from django.core.management.base import BaseCommand, CommandError
from src.dids.models import DIDDocument
from src.dids.utils.validators import validate_did_document
from src.dids.services import jcs_canonical_bytes, sha256_hex


class Command(BaseCommand):
    help = "Validate DID Document against platform schema and print JCS SHA-256"

    def add_arguments(self, parser):
        parser.add_argument("did_document_id", type=int)

    def handle(self, *args, **opts):
        doc = DIDDocument.objects.filter(pk=opts["did_document_id"]).first()
        if not doc:
            raise CommandError("DIDDocument not found")
        validate_did_document(doc.document)
        digest = sha256_hex(jcs_canonical_bytes(doc.document))
        self.stdout.write(self.style.SUCCESS(f"Valid ✓  JCS SHA-256: {digest}"))
