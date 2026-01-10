from enum import Enum


class EmailSendingStrategy(Enum):
    LOCAL = "local"
    PROVIDER = "provider"
