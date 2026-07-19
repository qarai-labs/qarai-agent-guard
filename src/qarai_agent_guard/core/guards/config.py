from enum import Enum


class FailBehavior(str, Enum):
    """Execution error fail behavior."""

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class SecurityMode(str, Enum):
    """Enforcement mode for policy decisions."""

    MONITOR = "monitor"
    ENFORCE = "enforce"


class ExecutionStrategy(str, Enum):
    """Execution strategy for running detectors."""

    FAIL_FAST = "fail_fast"
    EXHAUSTIVE = "exhaustive"
