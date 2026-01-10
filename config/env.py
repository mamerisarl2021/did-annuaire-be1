import environ
from django.core.exceptions import ImproperlyConfigured
import logging
from functools import lru_cache

import hvac

log = logging.getLogger(__name__)

env = environ.Env()

BASE_DIR = environ.Path(__file__) - 2
APPS_DIR = BASE_DIR.path("src")


def env_to_enum(enum_cls, value):
    for x in enum_cls:
        if x.value == value:
            return x

    raise ImproperlyConfigured(
        f"Env value {repr(value)} could not be found in {repr(enum_cls)}"
    )


# OpenBao connection (container vs host)
OPENBAO_ADDR = env("OPENBAO_ADDR", default="http://127.0.0.1:8200")
# Auth options: use OPENBAO_TOKEN for dev; prefer AppRole in prod (role+secret IDs)
OPENBAO_TOKEN = env("OPENBAO_TOKEN", default="")
OPENBAO_ROLE_ID = env("OPENBAO_ROLE_ID", default="")
OPENBAO_SECRET_ID = env("OPENBAO_SECRET_ID", default="")
# KV v2 mount/path (you enabled `secret` and wrote to `secret/django`)
OPENBAO_KV_MOUNT = env("OPENBAO_KV_MOUNT", default="secret")
OPENBAO_KV_PATH = env("OPENBAO_KV_PATH", default="django")  # e.g., "django", or "django/prod" if you split per env

def _bao_client() -> hvac.Client:
    # If TLS with custom CA: hvac.Client(url=..., verify="/path/to/ca.pem")
    return hvac.Client(url=OPENBAO_ADDR, timeout=5)

def _bao_auth(c: hvac.Client) -> None:
    # Priority: token (simple), else AppRole (prod), else unauth (will fail on read)
    if OPENBAO_TOKEN:
        c.token = OPENBAO_TOKEN
        return
    if OPENBAO_ROLE_ID and OPENBAO_SECRET_ID:
        resp = c.auth_approle(OPENBAO_ROLE_ID, OPENBAO_SECRET_ID)
        c.token = resp["auth"]["client_token"]

@lru_cache(maxsize=32)
def bao_read_kv(path = None) :
    """
    Read KV v2 dict at {OPENBAO_KV_MOUNT}/{path or OPENBAO_KV_PATH}.
    Cached per process.
    """
    c = _bao_client()
    _bao_auth(c)
    target_path = path or OPENBAO_KV_PATH
    resp = c.secrets.kv.v2.read_secret_version(mount_point=OPENBAO_KV_MOUNT, path=target_path)
    return resp["data"]["data"] or {}

def env_get(name: str, default = None, *, kv_path = None, prefer_env: bool = True) :
    """
    Unified accessor:
      1) .env / environment (via django-environ) if prefer_env and present
      2) OpenBao KV v2
      3) default
    """
    try:
        if prefer_env:
            val = env(name, default=None)  # django-environ reads from os.environ / .env
            if val is not None:
                return val
        data = bao_read_kv(kv_path)
        if name in data:
            return data[name]
    except Exception as e:
        log.warning("env_get: OpenBao fallback failed for %s: %s (using default)", name, e)
    return default
