from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from qarai_agent_guard.core.exceptions import ConfigurationError

DEFAULT_TIMEOUT = 60.0
CHAT_COMPLETIONS_PATH = "chat/completions"

API_MODEL_OPTION_KEYS = frozenset({"endpoint", "messages", "headers", "timeout"})
API_REQUIRED_MODEL_OPTION_KEYS = ("endpoint", "messages")
API_INFERENCE_OPTION_KEYS = frozenset(
    {
        "temperature",
        "max_tokens",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
        "response_format",
    }
)
_MESSAGE_KEYS = frozenset({"role", "content"})
_MESSAGE_ROLES = frozenset({"system", "user", "assistant"})
_NUMERIC_RANGES: dict[str, tuple[float, float]] = {
    "temperature": (0.0, 2.0),
    "top_p": (0.0, 1.0),
    "frequency_penalty": (-2.0, 2.0),
    "presence_penalty": (-2.0, 2.0),
}


def _as_options(value: Any, label: str) -> dict[str, Any]:
    """Copy an option bag, rejecting non-mapping values and non-string keys."""
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{label} must be a dict, got {type(value).__name__}")
    for key in value:
        if not isinstance(key, str):
            raise ConfigurationError(f"{label} keys must be strings, got {key!r}")
    return dict(value)


def _reject_unknown_keys(
    options: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
) -> None:
    unknown = sorted(set(options) - allowed)
    if unknown:
        raise ConfigurationError(
            f"unknown {label} key(s): {', '.join(unknown)}. "
            f"allowed keys: {', '.join(sorted(allowed))}"
        )


def validate_api_endpoint(value: Any) -> str:
    """Return the full chat-completions URL for a base endpoint.

    Only the base URL is accepted; the ``chat/completions`` suffix is
    appended here so callers cannot build double-suffixed URLs.

    Args:
        value (Any): Base URL configured under ``model_options['endpoint']``.

    Returns:
        str: Absolute URL ending with ``/chat/completions``.

    Raises:
        ConfigurationError: If the value is blank, not an absolute
            ``http(s)`` URL, or already includes the chat-completions path.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError("model_options['endpoint'] must be a non-empty string")
    base = value.strip().rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigurationError(
            "model_options['endpoint'] must be an absolute http(s) base URL, "
            f"got {value!r}"
        )
    if parsed.path.rstrip("/").endswith(f"/{CHAT_COMPLETIONS_PATH}"):
        raise ConfigurationError(
            "model_options['endpoint'] must be the base URL without the "
            f"'/{CHAT_COMPLETIONS_PATH}' suffix, got {value!r}"
        )
    return f"{base}/{CHAT_COMPLETIONS_PATH}"


def validate_api_messages(value: Any) -> list[dict[str, str]]:
    """Validate the chat messages sent before the verified text.

    Args:
        value (Any): Non-empty sequence of ``{"role": ..., "content": ...}``
            mappings. ``role`` must be ``system``, ``user`` or ``assistant``.

    Returns:
        list[dict[str, str]]: Normalized copies of the configured messages.

    Raises:
        ConfigurationError: If the sequence is empty or any entry has an
            unsupported role, a non-string content, or unknown keys.
    """
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ConfigurationError(
            "model_options['messages'] must be a list of "
            "{'role': ..., 'content': ...} dicts"
        )
    if not value:
        raise ConfigurationError("model_options['messages'] must not be empty")

    messages: list[dict[str, str]] = []
    for index, message in enumerate(value):
        label = f"model_options['messages'][{index}]"
        if not isinstance(message, Mapping):
            raise ConfigurationError(
                f"{label} must be a dict, got {type(message).__name__}"
            )
        _reject_unknown_keys(message, _MESSAGE_KEYS, label)
        for key in _MESSAGE_KEYS:
            if key not in message:
                raise ConfigurationError(f"{label} must define {key!r}")
        role = message["role"]
        content = message["content"]
        if not isinstance(role, str) or role not in _MESSAGE_ROLES:
            raise ConfigurationError(
                f"{label}['role'] must be one of: {', '.join(sorted(_MESSAGE_ROLES))}"
            )
        if not isinstance(content, str):
            raise ConfigurationError(f"{label}['content'] must be a string")
        messages.append({"role": role, "content": content})
    return messages


def validate_api_headers(value: Any) -> dict[str, str]:
    """Validate the extra HTTP headers configured under ``model_options``.

    Args:
        value (Any): Mapping of header names to string values.

    Returns:
        dict[str, str]: Copy of the validated headers.

    Raises:
        ConfigurationError: If a header name is blank or a value is not a
            string.
    """
    headers = _as_options(value, "model_options['headers']")
    for name, header_value in headers.items():
        if not name.strip():
            raise ConfigurationError("model_options['headers'] names must not be empty")
        if not isinstance(header_value, str):
            raise ConfigurationError(
                f"model_options['headers'][{name!r}] must be a string, "
                f"got {type(header_value).__name__}"
            )
    return headers


def validate_api_timeout(value: Any) -> float:
    """Validate the request timeout in seconds.

    Args:
        value (Any): Timeout configured under ``model_options['timeout']``.

    Returns:
        float: The timeout as a positive float.

    Raises:
        ConfigurationError: If the value is not a finite positive number.
            Invalid values are never silently replaced by the default.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigurationError(
            f"model_options['timeout'] must be a positive number, got {value!r}"
        )
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigurationError(
            f"model_options['timeout'] must be a finite positive number, got {value!r}"
        )
    return timeout


def _validate_response_format(value: Any) -> Any:
    if isinstance(value, str):
        if not value.strip():
            raise ConfigurationError(
                "inference_options['response_format'] must not be empty"
            )
        return value
    if isinstance(value, Mapping):
        if not value:
            raise ConfigurationError(
                "inference_options['response_format'] must not be empty"
            )
        return _as_options(value, "inference_options['response_format']")
    raise ConfigurationError(
        "inference_options['response_format'] must be a string or dict, "
        f"got {type(value).__name__}"
    )


def _validate_max_tokens(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigurationError(
            f"inference_options['max_tokens'] must be a positive integer, got {value!r}"
        )
    return value


def _validate_number(key: str, value: Any, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigurationError(
            f"inference_options[{key!r}] must be a number, got {value!r}"
        )
    if not math.isfinite(float(value)) or not low <= value <= high:
        raise ConfigurationError(
            f"inference_options[{key!r}] must be in [{low}, {high}], got {value!r}"
        )
    return value


def validate_api_inference_options(value: Any) -> dict[str, Any]:
    """Validate the request payload options of an API model config.

    Args:
        value (Any | None): ``ModelConfig.inference_options``. ``None``
            yields an empty mapping.

    Returns:
        dict[str, Any]: Copy of the validated options.

    Raises:
        ConfigurationError: If the bag is not a mapping, holds an unknown
            key, or any value falls outside its supported range.
    """
    if value is None:
        return {}
    options = _as_options(value, "inference_options")
    _reject_unknown_keys(options, API_INFERENCE_OPTION_KEYS, "inference_options")

    validated: dict[str, Any] = {}
    for key, item in options.items():
        if key in _NUMERIC_RANGES:
            low, high = _NUMERIC_RANGES[key]
            validated[key] = _validate_number(key, item, low, high)
        elif key == "max_tokens":
            validated[key] = _validate_max_tokens(item)
        else:
            validated[key] = _validate_response_format(item)
    return validated


def validate_api_model_options(value: Any) -> dict[str, Any]:
    """Validate the connection options of an API model config.

    Args:
        value (Any): ``ModelConfig.model_options``. Must define
            ``endpoint`` and ``messages``; ``headers`` and ``timeout`` are
            optional.

    Returns:
        dict[str, Any]: Normalized options with ``endpoint`` expanded to the
        full chat-completions URL, plus ``messages``, and ``headers`` /
        ``timeout`` when configured.

    Raises:
        ConfigurationError: If the bag is missing, holds an unknown key, or
            any value is invalid.
    """
    if value is None:
        raise ConfigurationError(
            "model_options is required for the API provider and must define: "
            f"{', '.join(API_REQUIRED_MODEL_OPTION_KEYS)}"
        )
    options = _as_options(value, "model_options")
    _reject_unknown_keys(options, API_MODEL_OPTION_KEYS, "model_options")

    missing = [key for key in API_REQUIRED_MODEL_OPTION_KEYS if key not in options]
    if missing:
        raise ConfigurationError(
            f"model_options is missing required key(s): {', '.join(missing)}. "
            f"allowed keys: {', '.join(sorted(API_MODEL_OPTION_KEYS))}"
        )

    validated: dict[str, Any] = {
        "endpoint": validate_api_endpoint(options["endpoint"]),
        "messages": validate_api_messages(options["messages"]),
    }
    if "headers" in options:
        validated["headers"] = validate_api_headers(options["headers"])
    if "timeout" in options:
        validated["timeout"] = validate_api_timeout(options["timeout"])
    return validated
