from enum import StrEnum


class FailBehavior(StrEnum):
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class SecurityMode(StrEnum):
    MONITOR = "monitor"
    ENFORCE = "enforce"


class ExecutionStrategy(StrEnum):
    FAIL_FAST = "fail_fast"
    EXHAUSTIVE = "exhaustive"
