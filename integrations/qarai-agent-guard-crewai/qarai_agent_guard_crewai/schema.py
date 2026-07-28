from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from qarai_agent_guard import Action


class HookName(StrEnum):
    BEFORE_LLM_CALL = "before_llm_call"
    AFTER_LLM_CALL = "after_llm_call"
    BEFORE_TOOL_CALL = "before_tool_call"
    AFTER_TOOL_CALL = "after_tool_call"


ALL_HOOKS = frozenset(h.value for h in HookName)


@dataclass
class EnforcementResult:
    """Outcome of enforcing a policy decision against some content."""

    content: Any
    action: Action
    blocked: bool = False
    redacted: bool = False


@dataclass
class _HookConfig:
    hooks: frozenset[str]
    fail_open: bool
    on_error: Callable[..., None] | None
    scan_all_messages: bool = False
