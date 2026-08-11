from qarai_agent_guard.core.exceptions import ModelProviderError
from qarai_agent_guard.core.models.providers.base import ModelProvider
from qarai_agent_guard.core.models.providers.huggingface import HuggingFaceProvider
from qarai_agent_guard.core.schemas.models import ModelConfig, ModelProviderName


class ModelProviderFactory:
    """Creates model providers from a model configuration."""

    @staticmethod
    def create(config: ModelConfig) -> ModelProvider:
        if not isinstance(config, ModelConfig):
            raise ModelProviderError("config must be a ModelConfig instance")

        if config.provider is ModelProviderName.HUGGINGFACE:
            return HuggingFaceProvider(config)

        raise ModelProviderError(f"Unsupported model provider: {config.provider}")
