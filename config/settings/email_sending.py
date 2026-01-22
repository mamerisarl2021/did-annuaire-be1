from config.env import env, env_to_enum
from src.emails.enums import EmailSendingStrategy

# local | provider
EMAIL_SENDING_STRATEGY = env_to_enum(
    EmailSendingStrategy, env("EMAIL_SENDING_STRATEGY", default="local")
)

EMAIL_SENDING_FAILURE_TRIGGER = env.bool("EMAIL_SENDING_FAILURE_TRIGGER", default=False)
EMAIL_SENDING_FAILURE_RATE = env.float("EMAIL_SENDING_FAILURE_RATE", default=0.2)

if EMAIL_SENDING_STRATEGY == EmailSendingStrategy.LOCAL:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

if EMAIL_SENDING_STRATEGY == EmailSendingStrategy.PROVIDER:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = env("EMAIL_HOST")
    EMAIL_HOST_USER = env("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
    EMAIL_PORT = env.int("EMAIL_PORT")
    EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS")
    # EMAIL_USE_SSL = env_get("EMAIL_USE_SSL")
    DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL")
    SERVER_EMAIL = EMAIL_HOST_USER
    ADMIN_USER_EMAIL = env("ADMIN_USER_EMAIL")
    ADMIN_USER_NAME = env("ADMIN_USER_NAME")
