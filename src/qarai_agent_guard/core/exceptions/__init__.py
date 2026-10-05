class GuardError(Exception):
    """Base exception for all agent-guard errors."""


class ConfigurationError(GuardError, ValueError):
    """Raised when the guard configuration is invalid."""


class ModelProviderError(GuardError):
    """Raised when a model provider operation fails."""


class ModelLoadError(ModelProviderError):
    """Raised when the model cannot be loaded."""


class ModelInferenceError(ModelProviderError):
    """Raised when model inference fails."""


class ModelRateLimitError(ModelInferenceError):
    """Raised when a remote API rejects a request with HTTP 429."""


class ModelOutputError(ModelProviderError):
    """Raised when the model produces invalid output."""


class ModelFormatterError(ModelProviderError):
    """Raised when model input or output formatting fails."""


class DetectorExecutionError(GuardError):
    """Raised when a detector fails during execution."""


class PolicyEvaluationError(GuardError):
    """Raised when policy evaluation fails."""


class RedactionError(GuardError):
    """Raised when content redaction fails."""


class AgentGuardViolation(GuardError):
    """Raised when AgentGuard blocks or quarantines content."""


class PatternLoaderError(ValueError):
    """Raised when a pattern file is invalid or cannot be processed."""


class PolicyLoaderError(ValueError):
    """Raised when a policy file is invalid or cannot be parsed."""


class StringifyError(ValueError):
    """Raised when a value cannot be converted to text safely."""


__all__ = [
    "AgentGuardViolation",
    "ConfigurationError",
    "DetectorExecutionError",
    "GuardError",
    "ModelFormatterError",
    "ModelInferenceError",
    "ModelLoadError",
    "ModelOutputError",
    "ModelProviderError",
    "ModelRateLimitError",
    "PatternLoaderError",
    "PolicyEvaluationError",
    "PolicyLoaderError",
    "RedactionError",
    "StringifyError",
]
