import structlog

from src.api.exception_handlers import custom_exception_handler

logger = structlog.get_logger(__name__)


class TriggerErrorApi:
    pass


class TriggerValidateUniqueErrorApi:
    pass


class TriggerUnhandledExceptionApi:
    pass
