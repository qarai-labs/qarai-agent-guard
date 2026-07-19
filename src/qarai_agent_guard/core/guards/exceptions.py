class GuardError(Exception):
    """Base exception for all agent guard errors."""


class DetectorExecutionError(GuardError):
    """Raised when a detector fails to execute."""


class PolicyEvaluationError(GuardError):
    """Raised when policy evaluation fails."""


class RedactionError(GuardError):
    """Raised when redaction fails."""
