from __future__ import annotations

from typing import Any

DEFAULT_MAX_DEPTH = 50


class StringifyError(ValueError):
    """Raised when a value cannot be safely converted to text."""


def _stringify(
    value: Any,
    *,
    _depth: int = 0,
    _max_depth: int = DEFAULT_MAX_DEPTH,
    _seen: set[int] | None = None,
) -> str:
    """Convert arbitrary values into a flat string for pattern matching.

    Recursively stringifies collections and mappings so detectors can scan
    structured payloads consistently.

    Args:
        value (Any): Value to convert. Required.
        _max_depth (int): Maximum recursion depth allowed for nested
            collections/mappings. Guards against circular references and
            excessively deep or maliciously crafted payloads.

    Returns:
        str: String representation suitable for regex inspection.

    Raises:
        StringifyError: If ``value`` contains a circular reference, exceeds
            ``_max_depth``, or contains an object whose ``__str__``/
            ``__repr__`` raises.
    """
    if _seen is None:
        _seen = set()

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, list | tuple | set | dict):
        if _depth >= _max_depth:
            raise StringifyError(
                f"maximum nesting depth ({_max_depth}) exceeded "
                "while stringifying value"
            )

        value_id = id(value)

        if value_id in _seen:
            raise StringifyError("circular reference detected while stringifying value")

        _seen = _seen | {value_id}

        if isinstance(value, dict):
            try:

                def stringify_entry(key: Any, item: Any) -> str:
                    stringified_key = _stringify(
                        key,
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                        _seen=_seen,
                    )
                    stringified_value = _stringify(
                        item,
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                        _seen=_seen,
                    )
                    return f"{stringified_key}: {stringified_value}"

                return "\n".join(
                    stringify_entry(key, item) for key, item in value.items()
                )
            except StringifyError:
                raise
            except Exception as exc:
                raise StringifyError(f"failed to stringify dict entry: {exc}") from exc

        try:
            return "\n".join(
                _stringify(
                    item,
                    _depth=_depth + 1,
                    _max_depth=_max_depth,
                    _seen=_seen,
                )
                for item in value
            )
        except StringifyError:
            raise
        except Exception as exc:
            raise StringifyError(
                f"failed to stringify collection entry: {exc}"
            ) from exc

    try:
        return str(value)
    except Exception as exc:
        raise StringifyError(
            f"failed to stringify value of type {type(value).__name__}: {exc}"
        ) from exc
