from __future__ import annotations

from typing import Any


def _stringify(value: Any) -> str:
    """Convert arbitrary values into a flat string for pattern matching.

    Recursively stringifies collections and mappings so detectors can scan
    structured payloads consistently.

    Args:
        value (Any): Value to convert. Required.

    Returns:
        str: String representation suitable for regex inspection.
    """
    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (list, tuple, set)):
        return "\n".join(_stringify(v) for v in value)

    if isinstance(value, dict):
        return "\n".join(f"{k}: {_stringify(v)}" for k, v in value.items())

    return str(value)
