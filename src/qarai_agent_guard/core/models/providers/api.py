from __future__ import annotations

from typing import Any

import httpx

from qarai_agent_guard.core.exceptions import (
    ConfigurationError,
    ModelInferenceError,
    ModelLoadError,
    ModelRateLimitError,
)
from qarai_agent_guard.core.helpers.api_options import (
    DEFAULT_TIMEOUT,
    validate_api_inference_options,
    validate_api_model_options,
)
from qarai_agent_guard.core.helpers.api_response import (
    error_detail,
    extract_message_content,
    retry_after_hint,
)
from qarai_agent_guard.core.logger import logger
from qarai_agent_guard.core.models.providers.base import ModelProvider
from qarai_agent_guard.core.schemas.models import ModelConfig, ModelProviderName


class APIProvider(ModelProvider):
    """Call an OpenAI-compatible ``chat/completions`` endpoint.

    The provider performs no output normalization: it returns the assistant
    message content so :class:`InferenceEngine` can format it.

    Configuration is split in two and validated on ``load``:

    ``model_options`` (connection setup)
        ``endpoint`` (required base URL, ``chat/completions`` is appended
        internally), ``messages`` (required, the configured chat history sent
        before the verified text), ``headers`` (optional extra HTTP headers)
        and ``timeout`` (optional request timeout in seconds).

    ``inference_options`` (request payload)
        ``temperature``, ``max_tokens``, ``top_p``, ``frequency_penalty``,
        ``presence_penalty`` and ``response_format``.

    Any other key in either mapping raises :class:`ConfigurationError`.
    """

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._client: httpx.Client | None = None
        self._loaded = False
        self._endpoint: str | None = None
        self._api_key: str = ""
        self._model: str | None = None
        self._messages: list[dict[str, str]] = []
        self._headers: dict[str, str] = {}
        self._timeout: float = DEFAULT_TIMEOUT
        self._inference_options: dict[str, Any] = {}

    def load(self) -> None:
        if self._loaded:
            return

        if self.config.provider is not ModelProviderName.API:
            raise ModelLoadError(
                f"APIProvider requires provider 'api', got {self.config.provider!r}"
            )

        api_key = self.config.api_key
        if not isinstance(api_key, str) or not api_key.strip():
            raise ConfigurationError("api_key is required for API provider")

        model_options = validate_api_model_options(self.config.model_options)
        self._inference_options = validate_api_inference_options(
            self.config.inference_options
        )

        self._endpoint = model_options["endpoint"]
        self._messages = model_options["messages"]
        self._headers = model_options.get("headers", {})
        self._timeout = model_options.get("timeout", DEFAULT_TIMEOUT)
        self._api_key = api_key.strip()
        self._model = self.config.model
        self._client = httpx.Client(timeout=self._timeout)
        self._loaded = True
        logger.info("APIProvider: ready to POST to %s", self._endpoint)

    def predict(self, text: str) -> Any:
        if not isinstance(text, str):
            raise ModelInferenceError("text must be a string")
        if not self._loaded or self._client is None or self._endpoint is None:
            raise ModelInferenceError("provider has not been loaded")

        request_body: dict[str, Any] = {
            "model": self._model,
            "messages": [*self._messages, {"role": "user", "content": text}],
            **self._inference_options,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            **self._headers,
        }

        try:
            response = self._client.post(
                self._endpoint, json=request_body, headers=headers
            )
        except httpx.HTTPError as exc:
            raise ModelInferenceError(
                f"API request to {self._endpoint} failed: {exc}"
            ) from exc

        if response.status_code == 429:
            raise ModelRateLimitError(
                f"API rate limit reached (429) for {self._endpoint}"
                f"{retry_after_hint(response)}: {error_detail(response)}"
            )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ModelInferenceError(
                f"API request failed with status {response.status_code}: "
                f"{error_detail(response)}"
            ) from exc

        return extract_message_content(response)

    def unload(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
        self._loaded = False
