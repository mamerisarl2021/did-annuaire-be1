"""
ASGI config for did_annuaire_be1 project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

ENV = os.environ.get("DJANGO_ENV", "development")
if ENV == "production":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")
elif ENV == "test":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.test")
else:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.base")
application = get_asgi_application()
