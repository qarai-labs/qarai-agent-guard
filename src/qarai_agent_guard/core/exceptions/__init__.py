class GuardError(Exception):
    """Base exception for agent-guard errors."""


class ConfigurationError(GuardError, ValueError):
    pass


class ModelProviderError(GuardError):
    pass


class ModelLoadError(ModelProviderError):
    pass


class ModelInferenceError(ModelProviderError):
    pass


class ModelOutputError(ModelProviderError):
    pass


class ModelFormatterError(ModelProviderError):
    pass


class DetectorExecutionError(GuardError):
    pass


class PolicyEvaluationError(GuardError):
    pass


class RedactionError(GuardError):
    pass
