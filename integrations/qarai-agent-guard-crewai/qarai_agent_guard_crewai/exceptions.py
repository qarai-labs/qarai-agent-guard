class AgentGuardViolation(Exception):
    """Raised when AgentGuard blocks or quarantines content."""


class AgentGuardHookError(Exception):
    """Raised when a hook itself fails unexpectedly (bug, bad context, etc.)."""
