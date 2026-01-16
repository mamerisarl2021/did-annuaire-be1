from .base import *  # noqa

env.read_env(os.path.join(BASE_DIR, ".env.backend"))

DEBUG = env_get("DEBUG", default=False)

SECRET_KEY = env_get("DJANGO_SECRET_KEY")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[])

CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS", default=[]
)  # empty cos fe and be are on same domain

SESSION_COOKIE_SECURE = env_get("SESSION_COOKIE_SECURE", default=True)
CSRF_COOKIE_SECURE = env_get("CSRF_COOKIE_SECURE", default=True)
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_get("SECURE_SSL_REDIRECT", default=True)
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = env_get("SECURE_CONTENT_TYPE_NOSNIFF", default=True)
