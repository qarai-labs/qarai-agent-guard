from enum import StrEnum


class DetectorType(StrEnum):
    REGEX = "regex"
    MODEL = "model"
    MIXED = "mixed"


class DefaultRules(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    PII = "pii"
    SECRETS = "secrets"


class CombinationStrategy(StrEnum):
    ANY = "any"
    ALL = "all"
    PRECEDENCE = "precedence"
