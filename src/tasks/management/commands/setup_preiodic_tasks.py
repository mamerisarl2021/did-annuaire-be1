from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.timezone import get_default_timezone_name
from django_celery_beat.models import CrontabSchedule, PeriodicTask

# If a task was declared as:
#   `@shared_task`(name="jwt.flush_expired_tokens")
# then task name = "jwt.flush_expired_tokens"
# If no name is given (e.g., debug_task), Celery uses dotted path, e.g. "src.tasks.tasks.debug_task"

TASK_SPECS = [
    {
        "name": "JWT: flush expired tokens (daily 03:15)",
        "task_name": "jwt.flush_expired_tokens",
        "cron": {"minute": "15", "hour": "3", "day_of_week": "*", "day_of_month": "*", "month_of_year": "*"},
        "enabled": True,
    },
    {
        "name": "Debug heartbeat (every minute)",
        "task_name": "src.tasks.tasks.debug_task",
        "cron": {"minute": "*/1", "hour": "*", "day_of_week": "*", "day_of_month": "*", "month_of_year": "*"},
        "enabled": False,
    },
    # add more entries here as needed
]


class Command(BaseCommand):
    help = "Setup Celery Beat periodic tasks"

    @transaction.atomic
    def handle(self, *args, **kwargs):
        tz = get_default_timezone_name()
        for spec in TASK_SPECS:
            cron, _ = CrontabSchedule.objects.get_or_create(timezone=tz, **spec["cron"])
            PeriodicTask.objects.update_or_create(
                name=spec["name"],
                defaults={"task": spec["task_name"], "crontab": cron, "enabled": spec.get("enabled", True)},
            )
            self.stdout.write(self.style.SUCCESS(f"Scheduled: {spec['name']}"))

# class Command(BaseCommand):
#     help = """
#     Setup celery beat periodic tasks.

#     Following tasks will be created:

#         - ....
#     """

#     @transaction.atomic
#     def handle(self, *args, **kwargs):
#         print("Deleting all periodic tasks and schedules...\n")

#         IntervalSchedule.objects.all().delete()
#         CrontabSchedule.objects.all().delete()
#         PeriodicTask.objects.all().delete()

#         """
#         Example:
#         {
#             'task': periodic_task_name,
#             'name': 'Periodic task description',
#             # Everyday at 15:45
#             # https://crontab.guru/#45_15_*_*_*
#             'cron': {
#                 'minute': '45',
#                 'hour': '15',
#                 'day_of_week': '*',
#                 'day_of_month': '*',
#                 'month_of_year': '*',
#             },
#             'enabled': True
#         },
#         """
#         periodic_tasks_data = []

#         timezone = get_default_timezone_name()

#         for periodic_task in periodic_tasks_data:
#             print(f"Setting up {periodic_task['task'].name}")

#             cron = CrontabSchedule.objects.create(
#                 timezone=timezone, **periodic_task["cron"]
#             )

#             PeriodicTask.objects.create(
#                 name=periodic_task["name"],
#                 task=periodic_task["task"].name,
#                 crontab=cron,
#                 enabled=periodic_task["enabled"],
#             )
