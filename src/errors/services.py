
import inspect
import sys

from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404

from src.core.exceptions import ApplicationError
from src.users.models import User

def trigger_django_validation():
    raise DjangoValidationError("Some error message")

def trigger_django_permission_denied():
    raise PermissionDenied()

def trigger_django_object_does_not_exist():
    raise ObjectDoesNotExist()

def trigger_django_404():
    raise Http404()

def trigger_model_clean():
    user = User()
    user.full_clean()
def trigger_rest_validation_plain():
    raise ("Some error message")

def trigger_rest_validation_detail():
    raise (detail={"error": "Some error message"})

def trigger_rest_throttled():


def trigger_rest_unsupported_media_type():


def trigger_rest_not_acceptable():


def trigger_rest_method_not_allowed():


def trigger_rest_not_found():


def trigger_rest_permission_denied():


def trigger_rest_not_authenticated():


def trigger_rest_authentication_failed():


def trigger_rest_parse_error():



def trigger_application_error():
    raise ApplicationError(message="Something is not correct", extra={"type": "RANDOM"})

def trigger_errors(exception_handler):
    result = {}

    for name, member in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(member) and name.startswith("trigger") and name != "trigger_errors":
            try:
                member()
            except Exception as exc:
                response = exception_handler(exc, {})

                if response is None:
                    result[name] = "500 SERVER ERROR"
                    continue

                result[name] = response.data

    return result
