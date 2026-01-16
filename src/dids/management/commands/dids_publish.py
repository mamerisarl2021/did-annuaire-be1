from django.core.management.base import BaseCommand, CommandError
from src.dids.models import DIDDocument
from src.dids.services import publish_preprod, publish_prod

class Command(BaseCommand):
    help = "Publish a DID Document to PREPROD or PROD"

    def add_arguments(self, parser):
        parser.add_argument("--env", choices=["preprod", "prod"], required=True)
        parser.add_argument("did_document_id", type=int)

    def handle(self, *args, **opts):
        doc = DIDDocument.objects.filter(pk=opts["did_document_id"]).select_related("did","did__organization","did__owner").first()
        if not doc:
            raise CommandError("DIDDocument not found")
        if opts["env"] == "preprod":
            url = publish_preprod(doc)
        else:
            url = publish_prod(doc)
        self.stdout.write(self.style.SUCCESS(f"Published to: {url}"))
