from __future__ import annotations

from typing import Any

import httpx

from qarai_agent_guard.core.exceptions import ModelOutputError

ERROR_DETAIL_LIMIT = 500


def error_detail(response: httpx.Response) -> str:
    """Return a bounded response body for error messages.

    Args:
        response (httpx.Response): Failed response to describe.

    Returns:
        str: The response text, truncated to
        :data:`ERROR_DETAIL_LIMIT` characters.
    """
    text = response.text
    if len(text) > ERROR_DETAIL_LIMIT:
        return text[:ERROR_DETAIL_LIMIT] + "..."
    return text


def retry_after_hint(response: httpx.Response) -> str:
    """Return the ``Retry-After`` hint of a throttled response, if any.

    Args:
        response (httpx.Response): Response rejected with HTTP 429.

    Returns:
        str: ``", retry after <value>"`` when the header is present,
        otherwise an empty string.
    """
    retry_after = response.headers.get("retry-after")
    return f", retry after {retry_after}" if retry_after else ""


def extract_message_content(response: httpx.Response) -> Any:
    """Return the assistant message content of a chat-completions response.

    Args:
        response (httpx.Response): Successful response to read.

    Returns:
        Any: The raw ``choices[0].message.content`` value.

    Raises:
        ModelOutputError: If the body is not JSON or does not follow the
            chat-completions shape.
    """
    try:
        data = response.json()
    except ValueError as exc:
        raise ModelOutputError(f"API response is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ModelOutputError("API response must be a JSON object")

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelOutputError("API response is missing a non-empty 'choices' list")

    choice = choices[0]
    if not isinstance(choice, dict):
        raise ModelOutputError("API response 'choices[0]' must be a JSON object")

    message = choice.get("message")
    if not isinstance(message, dict):
        raise ModelOutputError("API response is missing 'choices[0].message'")

    content = message.get("content")
    if content is None:
        raise ModelOutputError(
            "API response is missing 'choices[0].message.content'"
            f"{_truncation_hint(choice)}"
        )
    return content


def _truncation_hint(choice: dict[str, Any]) -> str:
    """Return a hint when the answer is missing because it was cut off.

    Reasoning models can spend the whole token budget on internal reasoning,
    which leaves the answer content empty.

    Args:
        choice (dict[str, Any]): The ``choices[0]`` entry of the response.

    Returns:
        str: An explanatory suffix, or an empty string.
    """
    if choice.get("finish_reason") != "length":
        return ""
    return (
        " (finish_reason='length': raise 'max_tokens' so the model can finish "
        "its answer)"
    )
