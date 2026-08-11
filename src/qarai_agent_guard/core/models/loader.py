from __future__ import annotations

import json
import threading

from qarai_agent_guard.core.exceptions import ConfigurationError, ModelLoadError
from qarai_agent_guard.core.models.providers import (
    ModelProvider,
    ModelProviderFactory,
)
from qarai_agent_guard.core.schemas.models import ModelConfig


class ModelLoader:
    """
    Loads, caches, and manages the lifecycle of model providers.

    Providers are cached according to their runtime model configuration so that
    multiple detectors using the same model can reuse the same loaded provider.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ModelProvider] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(config: ModelConfig) -> str:
        """
        Build a deterministic cache key for the loaded model provider.

        Only configuration that affects the loaded provider should participate
        in the key. Detection-level settings such as threshold and output
        formatter must not create separate model instances.
        """
        if not isinstance(config, ModelConfig):
            raise ConfigurationError("config must be a ModelConfig instance")

        try:
            return json.dumps(
                {
                    "provider": config.provider.value,
                    "model": config.model,
                    "task": config.task.value,
                    "model_options": config.model_options or {},
                    "tokenizer_options": config.tokenizer_options or {},
                },
                sort_keys=True,
                default=str,
            )
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "ModelConfig contains options that cannot be used to build a cache key"
            ) from exc

    def get(self, config: ModelConfig) -> ModelProvider:
        """
        Return a loaded provider for the given configuration.

        The provider is created and loaded lazily on first access. Providers
        that fail to load are not added to the cache.
        """
        key = self._key(config)

        with self._lock:
            provider = self._cache.get(key)
            if provider is not None:
                return provider

            try:
                provider = ModelProviderFactory.create(config)
                provider.load()
            except Exception as exc:
                raise ModelLoadError(
                    f"Failed to load model '{config.model}' "
                    f"using provider '{config.provider.value}'"
                ) from exc

            self._cache[key] = provider
            return provider

    def release(self, config: ModelConfig) -> None:
        """
        Remove and unload the provider associated with ``config``.

        If no provider is cached for the configuration, this method does
        nothing.
        """
        key = self._key(config)

        with self._lock:
            provider = self._cache.pop(key, None)

        if provider is None:
            return

        try:
            provider.unload()
        except Exception as exc:
            raise ModelLoadError(f"Failed to unload model '{config.model}'") from exc

    def clear(self) -> None:
        """
        Remove and unload all cached providers.

        Every cached provider is given an opportunity to unload even if
        another provider fails during cleanup.
        """
        with self._lock:
            providers = list(self._cache.values())
            self._cache.clear()

        errors: list[Exception] = []

        for provider in providers:
            try:
                provider.unload()
            except Exception as exc:
                errors.append(exc)

        if errors:
            raise ModelLoadError(
                f"Failed to unload {len(errors)} model provider(s)"
            ) from errors[0]
