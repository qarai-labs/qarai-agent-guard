from __future__ import annotations

from qarai_agent_guard.core.helpers.stringify import _stringify


def test_stringify_none():
    assert _stringify(None) == ""


def test_stringify_list():
    assert "a" in _stringify(["a", "b"])


def test_stringify_dict():
    result = _stringify({"key": "value"})
    assert "key: value" in result
