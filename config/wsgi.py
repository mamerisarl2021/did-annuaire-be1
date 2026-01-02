"""
WSGI config for did_annuaire_be1 project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

ENV = os.environ.get("DJANGO_ENV", "development")
if ENV == "production":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")
elif ENV == "test":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.test")
else:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.base")

application = get_wsgi_application()
