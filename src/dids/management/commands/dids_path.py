from django.core.management.base import BaseCommand
from src.dids.services import build_relpath, build_host


class Command(BaseCommand):
    help = "Compute public URL for a given env/org/user/type"

    def add_arguments(self, parser):
        parser.add_argument("--env", choices=["preprod", "prod"], required=True)
        parser.add_argument("organization_slug", type=str)
        parser.add_argument("user_slug", type=str)
        parser.add_argument("document_type", type=str)

    def handle(self, *args, **opts):
        env = "PREPROD" if opts["env"] == "preprod" else "PROD"
        rel = build_relpath(
            env, opts["organization_slug"], opts["user_slug"], opts["document_type"]
        )
        self.stdout.write(f"https://{build_host()}/{rel}")
