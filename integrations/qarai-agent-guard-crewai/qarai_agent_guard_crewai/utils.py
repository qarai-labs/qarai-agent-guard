from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("qarai_agent_guard.crewai")


def _get_attr_or_key(obj: Any, name: str, default: Any = None) -> Any:
    """CrewAI contexts are usually objects, but be liberal: support dicts too."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _message_to_text(message: Any) -> str:
    """
    Extract text content from a single LLMMessage-like object.

    LLMMessage is typically a dict: {"role": ..., "content": ...}, but some
    LLM providers nest content as a list of parts (e.g. multimodal messages:
    [{"type": "text", "text": "..."}]). Handle both defensively.
    """
    content = _get_attr_or_key(message, "content", "")

    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
                continue
            part_text = _get_attr_or_key(part, "text")
            if isinstance(part_text, str):
                parts.append(part_text)
        return "\n".join(parts)

    # Last resort: stringify whatever it is rather than crashing.
    return str(content)


def _set_message_content(message: Any, new_text: str) -> None:
    """Best-effort in-place rewrite of a message's content after redaction."""
    if isinstance(message, dict):
        message["content"] = new_text
        return
    try:
        setattr(message, "content", new_text)
    except Exception:
        logger.warning("AgentGuard: could not write back redacted content to message")
