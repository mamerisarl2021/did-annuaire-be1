from config.env import env

CELERY_BROKER_URL = env("CELERY_BROKER_URL", default="amqp://guest:guest@rabbitmq//")
CELERY_RESULT_BACKEND = "django-db"

CELERY_TIMEZONE = "UTC"

CELERY_TASK_SOFT_TIME_LIMIT = 20  # seconds
CELERY_TASK_TIME_LIMIT = 30  # seconds
CELERY_TASK_MAX_RETRIES = 3
CELERY_IMPORTS = ("src.tasks.jwt",)
