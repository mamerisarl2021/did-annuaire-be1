import os
import sys
import logging
from django.core.management.base import BaseCommand, CommandError

try:
    import hvac
except Exception as e:
    hvac = None

LOG = logging.getLogger(__name__)


def _parse_dotenv(path: str) -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                data[k] = v
    except FileNotFoundError:
        pass
    return data


def _mask(val: str | None) -> str:
    if val is None:
        return "None"
    if not isinstance(val, str):
        return "<non-string>"
    n = len(val)
    if n <= 4:
        return "*" * n
    return val[:2] + "*" * (n - 4) + val[-2:]


class Command(BaseCommand):
    help = "Check OpenBao KV v2 secrets vs environment (exits non-zero if required keys are missing)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--addr",
            default=os.getenv("OPENBAO_ADDR", "http://127.0.0.1:8200"),
            help="OpenBao address (OPENBAO_ADDR).",
        )
        parser.add_argument(
            "--token",
            default=os.getenv("OPENBAO_TOKEN", ""),
            help="OpenBao token (dev/simple). Prefer AppRole in prod.",
        )
        parser.add_argument(
            "--role-id",
            default=os.getenv("OPENBAO_ROLE_ID", ""),
            help="AppRole RoleID (prod).",
        )
        parser.add_argument(
            "--secret-id",
            default=os.getenv("OPENBAO_SECRET_ID", ""),
            help="AppRole SecretID (prod).",
        )
        parser.add_argument(
            "--mount",
            default=os.getenv("OPENBAO_KV_MOUNT", "secret"),
            help="KV v2 mount point (default: secret).",
        )
        parser.add_argument(
            "--path",
            default=os.getenv("OPENBAO_KV_PATH", "django"),
            help="KV v2 path (default: django).",
        )
        parser.add_argument(
            "--required",
            nargs="+",
            default=(os.getenv("OPENBAO_REQUIRED", "DJANGO_SECRET_KEY").split(",")),
            help="Required keys list. Example: --required DJANGO_SECRET_KEY DATABASE_URL",
        )
        parser.add_argument(
            "--dotenv",
            default=os.getenv("ENV_FILE", ""),
            help="Optional dotenv file to read (ex: ./config.env).",
        )
        parser.add_argument("--json", action="store_true", help="Print JSON report.")

    def handle(self, *args, **opts):
        if hvac is None:
            raise CommandError("hvac is not installed. pip install hvac")

        addr: str = opts["addr"]
        token: str = opts["token"]
        role_id: str = opts["role_id"]
        secret_id: str = opts["secret_id"]
        mount: str = opts["mount"]
        path: str = opts["path"]
        required = [k.strip() for k in opts["required"] if k.strip()]
        dotenv_path: str = opts["dotenv"]
        as_json: bool = opts["json"]

        # Load dotenv if provided
        dotenv_map: dict[str, str] = _parse_dotenv(dotenv_path) if dotenv_path else {}

        # Prepare hvac client and authenticate
        client = hvac.Client(url=addr, timeout=5)
        auth_method = None
        try:
            if token:
                client.token = token
                auth_method = "token"
            elif role_id and secret_id:
                resp = client.auth_approle(role_id, secret_id)
                client.token = resp["auth"]["client_token"]
                auth_method = "approle"
            else:
                auth_method = "none"
        except Exception as e:
            if as_json:
                import json

                print(json.dumps({"ok": False, "error": f"auth_failed: {str(e)}"}))
                sys.exit(1)
            raise CommandError(f"OpenBao auth failed: {e}")

        # Read KV v2
        kv_data: dict[str, str] = {}
        kv_ok = False
        kv_err: str | None = None
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                mount_point=mount, path=path
            )
            kv_data = resp["data"]["data"] or {}
            kv_ok = True
        except Exception as e:
            kv_err = str(e)

        report = []
        missing = []
        for key in required:
            if key in kv_data:
                source = "KV"
                value = kv_data.get(key)
            elif key in os.environ:
                source = "ENV"
                value = os.environ.get(key)
            elif key in dotenv_map:
                source = "DOTENV"
                value = dotenv_map.get(key)
            else:
                source = "MISSING"
                value = None
                missing.append(key)
            report.append({"key": key, "source": source, "value": value})

        # Output
        if as_json:
            import json

            out = {
                "openbao": {
                    "addr": addr,
                    "auth": auth_method,
                    "kv_ok": kv_ok,
                    "mount": mount,
                    "path": path,
                    "error": kv_err,
                },
                "dotenv": {"path": dotenv_path or None, "loaded": bool(dotenv_map)},
                "required": required,
                "report": [
                    {
                        "key": r["key"],
                        "source": r["source"],
                        "value_masked": _mask(r["value"]),
                    }
                    for r in report
                ],
                "missing": missing,
                "ok": len(missing) == 0,
            }
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            self.stdout.write(
                self.style.NOTICE(
                    f"OpenBao: addr={addr} auth={auth_method} mount={mount} path={path} kv_ok={kv_ok}"
                )
            )
            if kv_err:
                self.stderr.write(
                    self.style.WARNING(f"OpenBao KV read error: {kv_err}")
                )
            if dotenv_path:
                self.stdout.write(
                    self.style.NOTICE(
                        f"Dotenv: {dotenv_path} loaded={bool(dotenv_map)}"
                    )
                )
            self.stdout.write(self.style.SUCCESS("Required keys status:"))
            for r in report:
                self.stdout.write(
                    f"  {r['key']:>24}  {r['source']:<7}  {_mask(r['value'])}"
                )
            if missing:
                self.stderr.write(
                    self.style.ERROR(f"Missing required: {', '.join(missing)}")
                )

        if missing:
            sys.exit(1)
        sys.exit(0)
