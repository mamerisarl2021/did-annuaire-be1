from django.apps import AppConfig


class AuditactionConfig(AppConfig):
    name = 'src.auditaction'

    def ready(self):
        # Connect auth signals → audit entries
        try:
            from . import signals  # noqa: F401
        except Exception:
            # Avoid hard failure if DB not migrated yet
            pass
