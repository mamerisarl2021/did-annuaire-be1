from .base import *  # noqa

DEBUG = env.bool("DEBUG", default=False) # noqa

SECRET_KEY = env("DJANGO_SECRET_KEY") # noqa

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[]) # noqa

CORS_ALLOW_ALL_ORIGINS = env.bool("CORS_ALLOW_ALL_ORIGINS", default=False)
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS", default=[]
)  # empty cos fe and be are on same domain
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=True) # noqa
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[]) # noqa
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True) # noqa
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = env.bool("SECURE_CONTENT_TYPE_NOSNIFF", default=True) # noqa
