import multiprocessing
import logging.config
import re

import structlog


# Recommended: 2-4 workers per CPU core for Django
cpu_count = multiprocessing.cpu_count()
max_workers = 10
workers = min(cpu_count * 2 + 1, max_workers)

# Prevent stuck workers
timeout = 60
keepalive = 5

# Graceful handling
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 50

# Logging
loglevel = "info"  # debug in prod is too verbose
errorlog = "-"
accesslog = "-"

# Custom access log format that includes host header
# Exemple de ligne :
# 192.168.1.1 - user [27/Dec/2025:17:30:00 +0000] "GET /path HTTP/1.1" 200 123 "-" "curl/8.0" host="api.example.com"
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" host="%({Host}i)s"'
)


# Performance
worker_class = "sync"  # Django works best with sync workers
preload_app = True


def combined_logformat(logger, name, event_dict):
    """
    Parse la ligne d'access log de Gunicorn pour en extraire des champs structurés.
    Reste tolérant si le format ne matche pas exactement.
    """
    if event_dict.get("logger") == "gunicorn.access":
        message = event_dict.get("event", "")

        parts = [
            r"(?P<host>\S+)",  # %h
            r"\S+",  # %l (unused)
            r"(?P<user>\S+)",  # %u
            r"\[(?P<time>.+)\]",  # %t
            r'"(?P<request>.+)"',  # "%r"
            r"(?P<status>[0-9]+)",  # %s
            r"(?P<size>\S+)",  # %b
            r'"(?P<referer>.*)"',  # "%{Referer}i"
            r'"(?P<agent>.*)"',  # "%{User-agent}i"
            r'host="(?P<host_header>.*)"',  # "%({Host}i)s"
        ]
        pattern = re.compile(r"\s+".join(parts) + r"\s*\Z")
        m = pattern.match(message)

        # Si ça ne matche pas (format différent, ligne tronquée, etc.), on laisse tomber.
        if not m:
            return event_dict

        res = m.groupdict()

        # Normalisation des champs
        if res.get("user") == "-":
            res["user"] = None

        # status
        try:
            res["status"] = int(res["status"])
        except (TypeError, ValueError, KeyError):
            pass

        # size
        size_val = res.get("size")
        if size_val == "-":
            res["size"] = 0
        else:
            try:
                res["size"] = int(size_val)
            except (TypeError, ValueError):
                res["size"] = 0

        # referer
        if res.get("referer") == "-":
            res["referer"] = None

        event_dict.update(res)

        # request → method, path, version
        request = res.get("request", "")
        parts_req = request.split(" ")
        if len(parts_req) == 3:
            method, path, version = parts_req
            event_dict["method"] = method
            event_dict["path"] = path
            event_dict["version"] = version
        else:
            # On garde au moins la requête brute si on ne peut pas la découper
            event_dict["request_raw"] = request

    return event_dict


def gunicorn_event_name_mapper(logger, name, event_dict):
    """
    Normalise le champ event pour les logs gunicorn.error/access.
    Évite les KeyError si 'event' n'existe pas.
    """
    logger_name = event_dict.get("logger")

    if logger_name not in ["gunicorn.error", "gunicorn.access"]:
        return event_dict

    GUNICORN_BOOTING = "gunicorn.booting"
    GUNICORN_REQUEST = "gunicorn.request_handling"
    GUNICORN_SIGNAL = "gunicorn.signal_handling"

    raw_event = event_dict.get("event")
    if not isinstance(raw_event, str):
        return event_dict

    event = raw_event.lower()

    if logger_name == "gunicorn.error":
        event_dict["message"] = event

        if event.startswith(("starting", "listening", "using", "booting")):
            event_dict["event"] = GUNICORN_BOOTING

        if event.startswith("handling signal"):
            event_dict["event"] = GUNICORN_SIGNAL

    if logger_name == "gunicorn.access":
        event_dict["event"] = GUNICORN_REQUEST

    return event_dict


timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
pre_chain = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    timestamper,
    combined_logformat,
    gunicorn_event_name_mapper,
]

CONFIG_DEFAULTS = {
    "version": 1,
    "disable_existing_loggers": False,
    "root": {"level": "INFO", "handlers": ["default"]},
    "loggers": {
        "gunicorn.error": {
            "level": "INFO",
            "handlers": ["default"],
            "propagate": False,
            "qualname": "gunicorn.error",
        },
        "gunicorn.access": {
            "level": "INFO",
            "handlers": ["default"],
            "propagate": False,
            "qualname": "gunicorn.access",
        },
        # On lui met un handler pour ne pas perdre ses logs
        "django_structlog": {
            "level": "INFO",
            "handlers": ["default"],
            "propagate": False,
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "logfmt_formatter",
        },
    },
    "formatters": {
        "logfmt_formatter": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processor": structlog.processors.LogfmtRenderer(),
            "foreign_pre_chain": pre_chain,
        }
    },
}

logging.config.dictConfig(CONFIG_DEFAULTS)
