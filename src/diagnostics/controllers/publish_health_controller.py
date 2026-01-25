import os
import shutil
import pathlib

from django.conf import settings
from ninja_extra import api_controller, route
from ninja.errors import HttpError
from ninja_extra.throttling import DynamicRateThrottle

from src.core.apis import BaseAPIController
from src.core.policies import ensure_superuser

@api_controller("/diagnostics", tags=["Diagnostics"], throttle=[DynamicRateThrottle(scope="sustained")])
class PublishHealthController(BaseAPIController):
    @route.get("/publish-root")
    def publish_root(self, request):
        """
        Superuser-only diagnostics for the DID publish root (DIDS_ROOT).
        Reports path info, writability, disk usage, and sample fs path + public URL.
        """
        user = request.user
        if not ensure_superuser(user):
            raise HttpError(403, "Forbidden")

        root = getattr(settings, "DIDS_ROOT", "/app/data/dids/.well-known")
        host = getattr(settings, "DID_DOMAIN_HOST", "annuairedid-fe.qcdigitalhub.com")

        p = pathlib.Path(root)
        exists = p.exists()
        is_dir = p.is_dir()
        writable = os.access(root, os.W_OK)

        # Disk usage (use root if exists, else parent, else '/')
        probe_path = root if exists else (str(p.parent) if p.parent.exists() else "/")
        try:
            usage = shutil.disk_usage(probe_path)
            total_bytes = usage.total
            free_bytes = usage.free
        except Exception:
            total_bytes = None
            free_bytes = None

        # Example locations (for quick manual checks)
        example_org = "example-org"
        example_user = "example-user"
        example_type = "example-type"
        example_rel = f"{example_org}/{example_user}/{example_type}/did.json"
        example_fs_path = str(p / example_org / example_user / example_type / "did.json")
        example_url = f"https://{host}/{example_rel}"

        return self.create_response(
            message="OK",
            data={
                "root": root,
                "host": host,
                "exists": exists,
                "is_dir": is_dir,
                "writable": writable,
                "disk": {
                    "total_bytes": total_bytes,
                    "free_bytes": free_bytes,
                },
                "example": {
                    "fs_path": example_fs_path,
                    "url": example_url,
                },
            },
            status_code=200,
        )