from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from crewai.hooks import (
    after_llm_call,
    after_tool_call,
    before_llm_call,
    before_tool_call,
)
from qarai_agent_guard import AgentGuard

from qarai_agent_guard_crewai.agent_guard_adapter import AgentGuardAdapter
from qarai_agent_guard_crewai.exceptions import (
    AgentGuardHookError,
    AgentGuardViolation,
)
from qarai_agent_guard_crewai.schema import ALL_HOOKS, HookName, _HookConfig
from qarai_agent_guard_crewai.utils import (
    _get_attr_or_key,
    _message_to_text,
    _set_message_content,
    logger,
)


def enable_guard(
    guard: AgentGuard,
    *,
    hooks: Iterable[str] | None = None,
    fail_open: bool = True,
    on_error: Callable[..., None] | None = None,
    on_violation: Callable[..., None] | None = None,
    quarantine_handler: Callable[..., None] | None = None,
    scan_all_messages: bool = False,
) -> AgentGuardAdapter:
    """
    Register AgentGuard checks against CrewAI's hook system.

    Args:
        guard: A configured AgentGuard instance.
        hooks: Which hooks to register. Any subset of
            {"before_llm_call", "after_llm_call", "before_tool_call",
            "after_tool_call"}. Defaults to all four.
        fail_open: If True (default), an *unexpected* error inside a hook
            (bug, bad context shape, guard misconfiguration - NOT a policy
            BLOCK/QUARANTINE, which is intentional and always raised) is
            logged and swallowed so the crew keeps running. If False, the
            error is re-raised as AgentGuardHookError.
        on_error: Optional callback invoked with (hook=..., error=...)
            whenever a hook swallows or re-raises an unexpected error.
        on_violation: Optional callback invoked with (source=, decision=,
            content=) whenever AgentGuard blocks or quarantines content.
        quarantine_handler: Optional callback invoked when the policy
            action is QUARANTINE, receiving (source=, content=, decision=).
        scan_all_messages: If False (default), only the latest message is
            inspected before an LLM call. If True, all messages in the
            conversation are inspected on every call. The default avoids
            repeatedly scanning messages that were already inspected.

    Returns:
        The AgentGuardAdapter used internally, in case callers want
        to inspect `.violations` or reuse `.enforce()` elsewhere.

    Raises:
        ValueError: If `guard` is None or an invalid hook name is given.
    """
    if guard is None:
        raise ValueError("enable_guard requires a non-None AgentGuard instance")

    selected = frozenset(hooks) if hooks is not None else ALL_HOOKS
    unknown = selected - ALL_HOOKS
    if unknown:
        raise ValueError(
            f"Unknown hook name(s): {sorted(unknown)}. "
            f"Valid options are: {sorted(ALL_HOOKS)}"
        )

    adapter = AgentGuardAdapter(
        guard,
        quarantine_handler=quarantine_handler,
        on_violation=on_violation,
    )

    cfg = _HookConfig(
        hooks=selected,
        fail_open=fail_open,
        on_error=on_error,
        scan_all_messages=scan_all_messages,
    )

    def _handle_unexpected(hook_name: str, error: Exception, context: Any) -> None:
        logger.exception("AgentGuard: unexpected error in %s", hook_name)
        if cfg.on_error is not None:
            try:
                cfg.on_error(hook=hook_name, error=error, context=context)
            except Exception:
                logger.exception("AgentGuard: on_error callback raised")
        if not cfg.fail_open:
            raise AgentGuardHookError(
                f"AgentGuard hook {hook_name!r} failed"
            ) from error

    if HookName.BEFORE_LLM_CALL.value in selected:

        @before_llm_call
        def guard_validate_input(context):
            try:
                messages = _get_attr_or_key(context, "messages", None)
                if not messages:
                    return None

                messages_to_scan = (
                    list(messages) if scan_all_messages else [messages[-1]]
                )
                for i, message in enumerate(messages_to_scan):
                    text = _message_to_text(message)
                    if not text:
                        continue

                    idx = i if scan_all_messages else len(messages) - 1
                    key = "model_input"
                    source = f"crewai.before_llm_call:message_{idx}"

                    decision, detections = guard.check(
                        key=key,
                        value=text,
                        operation="input",
                    )
                    result = adapter.enforce(
                        decision=decision,
                        content=text,
                        detections=detections,
                        source=source,
                    )
                    if result.redacted:
                        _set_message_content(message, result.content)

                return None

            except AgentGuardViolation:
                raise
            except Exception as exc:
                _handle_unexpected("before_llm_call", exc, context)
                return None

    if HookName.AFTER_LLM_CALL.value in selected:

        @after_llm_call
        def guard_validate_output(context):
            try:
                response = _get_attr_or_key(context, "response", None)
                if response is None:
                    return None
                response_text = response

                decision, detections = guard.check(
                    key="model_output",
                    value=response_text,
                    operation="output",
                )
                result = adapter.enforce(
                    decision=decision,
                    content=response_text,
                    detections=detections,
                    source="crewai.after_llm_call",
                )

                if result.redacted:
                    try:
                        context.response = result.content
                    except Exception:
                        logger.warning(
                            "AgentGuard: could not write back redacted LLM response"
                        )

                return None

            except AgentGuardViolation:
                raise
            except Exception as exc:
                _handle_unexpected("after_llm_call", exc, context)
                return None

    if HookName.BEFORE_TOOL_CALL.value in selected:

        @before_tool_call
        def guard_validate_tool_call(context):
            try:
                tool_name = _get_attr_or_key(context, "tool_name", "unknown_tool")
                tool_input = _get_attr_or_key(context, "tool_input", {}) or {}

                decision, detections = guard.check(
                    key=f"tool_input:{tool_name}",
                    value=tool_input,
                    operation="tool_input",
                )
                result = adapter.enforce(
                    decision=decision,
                    content=tool_input,
                    detections=detections,
                    source=f"crewai.before_tool_call:{tool_name}",
                )

                if result.redacted and isinstance(result.content, dict):
                    tool_input.clear()
                    tool_input.update(result.content)

                return None

            except AgentGuardViolation:
                raise
            except Exception as exc:
                _handle_unexpected("before_tool_call", exc, context)
                return None

    if HookName.AFTER_TOOL_CALL.value in selected:

        @after_tool_call
        def guard_validate_tool_result(context):
            try:
                tool_name = _get_attr_or_key(context, "tool_name", "unknown_tool")
                tool_result = _get_attr_or_key(context, "tool_result", None)
                if tool_result is None:
                    return None
                result_text = tool_result

                decision, detections = guard.check(
                    key=f"tool_result:{tool_name}",
                    value=result_text,
                    operation="tool_result",
                )
                enforced = adapter.enforce(
                    decision=decision,
                    content=result_text,
                    detections=detections,
                    source=f"crewai.after_tool_call:{tool_name}",
                )

                if enforced.redacted:
                    try:
                        context.tool_result = enforced.content
                    except Exception:
                        logger.warning(
                            "AgentGuard: could not write back redacted tool result"
                        )

                return None

            except AgentGuardViolation:
                raise
            except Exception as exc:
                _handle_unexpected("after_tool_call", exc, context)
                return None

    logger.info(
        "AgentGuard: registered CrewAI hooks %s (fail_open=%s)",
        sorted(selected),
        fail_open,
    )
    return adapter
