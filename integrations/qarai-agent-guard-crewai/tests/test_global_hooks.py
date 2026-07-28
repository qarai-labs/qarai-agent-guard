from __future__ import annotations

from types import SimpleNamespace

import pytest
from crewai.hooks import (
    get_after_llm_call_hooks,
    get_after_tool_call_hooks,
    get_before_llm_call_hooks,
    get_before_tool_call_hooks,
)
from crewai.hooks.llm_hooks import LLMCallHookContext
from qarai_agent_guard import Action

from qarai_agent_guard_crewai.AgentGuardAdapter import AgentGuardAdapter
from qarai_agent_guard_crewai.exceptions import (
    AgentGuardHookError,
    AgentGuardViolation,
)
from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import CLEAN_TEXT, PII_TEXT, PROMPT_INJECTION_TEXT, SECRET_TEXT


def _make_llm_context(messages: list[dict] | None = None, response: str | None = None):
    """Build a minimal LLMCallHookContext without a real executor."""
    return LLMCallHookContext(
        executor=None,
        messages=messages or [],
        response=response,
    )


def _make_tool_context(
    tool_name: str = "test_tool",
    tool_input: dict | None = None,
    tool_result: str | None = None,
):
    """Build a minimal context object for tool hooks.

    We use SimpleNamespace because ToolCallHookContext requires a real
    CrewStructuredTool instance.  The hooks only access `.tool_name`,
    `.tool_input`, and `.tool_result` via _get_attr_or_key, so a
    namespace with those attrs is sufficient.
    """
    ns = SimpleNamespace(
        tool_name=tool_name,
        tool_input=tool_input or {},
        tool_result=tool_result,
    )
    return ns


def _fire_before_llm(context):
    """Manually invoke all registered before_llm_call hooks."""
    for hook in get_before_llm_call_hooks():
        hook(context)


def _fire_after_llm(context):
    """Manually invoke all registered after_llm_call hooks."""
    for hook in get_after_llm_call_hooks():
        hook(context)


def _fire_before_tool(context):
    """Manually invoke all registered before_tool_call hooks."""
    for hook in get_before_tool_call_hooks():
        hook(context)


def _fire_after_tool(context):
    """Manually invoke all registered after_tool_call hooks."""
    for hook in get_after_tool_call_hooks():
        hook(context)


class TestEnableGuardRegistration:
    """Verify enable_guard registers the right hooks and validates inputs."""

    def test_registers_all_hooks_by_default(self, guard):
        enable_guard(guard)
        assert len(get_before_llm_call_hooks()) >= 1
        assert len(get_after_llm_call_hooks()) >= 1
        assert len(get_before_tool_call_hooks()) >= 1
        assert len(get_after_tool_call_hooks()) >= 1

    def test_registers_selected_hooks_only(self, guard):
        enable_guard(guard, hooks=["before_llm_call"])
        assert len(get_before_llm_call_hooks()) >= 1
        assert len(get_after_llm_call_hooks()) == 0
        assert len(get_before_tool_call_hooks()) == 0
        assert len(get_after_tool_call_hooks()) == 0

    def test_registers_two_selected_hooks(self, guard):
        enable_guard(guard, hooks=["before_llm_call", "after_tool_call"])
        assert len(get_before_llm_call_hooks()) >= 1
        assert len(get_after_llm_call_hooks()) == 0
        assert len(get_before_tool_call_hooks()) == 0
        assert len(get_after_tool_call_hooks()) >= 1

    def test_rejects_unrecognized_hook(self, guard):
        with pytest.raises(ValueError, match="Unknown hook name"):
            enable_guard(guard, hooks=["on_model_start"])

    def test_rejects_partially_invalid_hooks(self, guard):
        with pytest.raises(ValueError, match="Unknown hook name"):
            enable_guard(guard, hooks=["before_llm_call", "nonexistent_hook"])

    def test_none_guard_raises(self):
        with pytest.raises(ValueError, match="non-None"):
            enable_guard(None)

    def test_returns_adapter(self, guard):
        adapter = enable_guard(guard)
        assert isinstance(adapter, AgentGuardAdapter)
        assert adapter.guard is guard


class TestBeforeLLMCallHook:
    """Test the before_llm_call guard hook with real detectors."""

    def test_clean_input_passes(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(messages=[{"role": "user", "content": CLEAN_TEXT}])
        _fire_before_llm(ctx)

    def test_prompt_injection_raises(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

    def test_pii_redacts_message_in_place(self, guard):
        enable_guard(guard)
        msg = {"role": "user", "content": PII_TEXT}
        ctx = _make_llm_context(messages=[msg])
        _fire_before_llm(ctx)
        assert "GB29NWBK60161331926819" not in msg["content"]

    def test_empty_messages_is_noop(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(messages=[])
        _fire_before_llm(ctx)

    def test_none_content_message_is_skipped(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(messages=[{"role": "assistant", "content": None}])
        _fire_before_llm(ctx)

    def test_scan_all_messages_true_catches_earlier_injection(self, guard):
        enable_guard(guard, scan_all_messages=True)
        messages = [
            {"role": "user", "content": PROMPT_INJECTION_TEXT},
            {"role": "assistant", "content": "Sure, here you go."},
            {"role": "user", "content": CLEAN_TEXT},
        ]
        ctx = _make_llm_context(messages=messages)
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

    def test_scan_all_messages_false_ignores_earlier_injection(self, guard):
        enable_guard(guard, scan_all_messages=False)
        messages = [
            {"role": "user", "content": PROMPT_INJECTION_TEXT},
            {"role": "assistant", "content": "Sure, here you go."},
            {"role": "user", "content": CLEAN_TEXT},
        ]
        ctx = _make_llm_context(messages=messages)
        _fire_before_llm(ctx)

    def test_scan_all_messages_default_is_false(self, guard):
        """The default scan_all_messages=False should only scan the last message."""
        enable_guard(guard)
        messages = [
            {"role": "user", "content": PROMPT_INJECTION_TEXT},
            {"role": "user", "content": CLEAN_TEXT},
        ]
        ctx = _make_llm_context(messages=messages)
        _fire_before_llm(ctx)

    def test_scan_all_messages_redacts_each_message_in_place(self, guard):
        enable_guard(guard, scan_all_messages=True)

        msg1 = {"role": "user", "content": PII_TEXT}
        msg2 = {"role": "user", "content": PII_TEXT}
        messages = [msg1, msg2]

        ctx = _make_llm_context(messages=messages)

        _fire_before_llm(ctx)

        assert "GB29NWBK60161331926819" not in msg1["content"]
        assert "GB29NWBK60161331926819" not in msg2["content"]

    def test_before_llm_source_contains_message_index(self, guard):
        sources = []

        def on_violation(*, source, decision, content):
            sources.append(source)

        enable_guard(
            guard,
            on_violation=on_violation,
            hooks=["before_llm_call"],
        )

        ctx = _make_llm_context(
            messages=[
                {"role": "user", "content": CLEAN_TEXT},
                {"role": "user", "content": PROMPT_INJECTION_TEXT},
            ]
        )

        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

        assert sources == ["crewai.before_llm_call:message_1"]


class TestAfterLLMCallHook:
    """Test the after_llm_call guard hook with real detectors."""

    def test_clean_response_passes(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(response=CLEAN_TEXT)
        _fire_after_llm(ctx)

    def test_injection_in_response_blocks(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(response=PROMPT_INJECTION_TEXT)
        with pytest.raises(AgentGuardViolation):
            _fire_after_llm(ctx)

    def test_pii_in_response_redacts(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(response=PII_TEXT)
        _fire_after_llm(ctx)
        assert "GB29NWBK60161331926819" not in ctx.response

    def test_none_response_is_noop(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(response=None)
        _fire_after_llm(ctx)

    def test_secrets_in_response_blocks(self, guard):
        enable_guard(guard)
        ctx = _make_llm_context(response=SECRET_TEXT)
        with pytest.raises(AgentGuardViolation):
            _fire_after_llm(ctx)


class TestBeforeToolCallHook:
    """Test the before_tool_call guard hook with real detectors."""

    def test_clean_input_passes(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_input={"query": CLEAN_TEXT})
        _fire_before_tool(ctx)

    def test_injection_in_tool_input_blocks(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_input={"query": PROMPT_INJECTION_TEXT})
        with pytest.raises(AgentGuardViolation):
            _fire_before_tool(ctx)

    def test_empty_tool_input_is_noop(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_input={})
        _fire_before_tool(ctx)


class TestAfterToolCallHook:
    """Test the after_tool_call guard hook with real detectors."""

    def test_clean_result_passes(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_result=CLEAN_TEXT)
        _fire_after_tool(ctx)

    def test_secrets_in_result_blocks(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_result=SECRET_TEXT)
        with pytest.raises(AgentGuardViolation):
            _fire_after_tool(ctx)

    def test_pii_in_result_redacts(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_result=PII_TEXT)
        _fire_after_tool(ctx)
        assert "GB29NWBK60161331926819" not in ctx.tool_result

    def test_none_result_is_noop(self, guard):
        enable_guard(guard)
        ctx = _make_tool_context(tool_result=None)
        _fire_after_tool(ctx)


class TestFailOpenBehaviour:
    """Verify fail_open controls how unexpected (non-policy) errors behave."""

    def _make_broken_context(self):
        """Return a context whose .messages triggers an unexpected error."""
        ctx = SimpleNamespace(messages=42)
        return ctx

    def test_fail_open_true_swallows_unexpected_error(self, guard):
        enable_guard(guard, fail_open=True, hooks=["before_llm_call"])
        ctx = self._make_broken_context()
        _fire_before_llm(ctx)

    def test_fail_open_false_raises_hook_error(self, guard):
        enable_guard(guard, fail_open=False, hooks=["before_llm_call"])
        ctx = self._make_broken_context()
        with pytest.raises(AgentGuardHookError, match="before_llm_call"):
            _fire_before_llm(ctx)

    def test_on_error_callback_invoked(self, guard):
        errors_received = []

        def error_recorder(*, hook, error, context=None):
            errors_received.append({"hook": hook, "error": error})

        enable_guard(
            guard,
            fail_open=True,
            on_error=error_recorder,
            hooks=["before_llm_call"],
        )
        ctx = self._make_broken_context()
        _fire_before_llm(ctx)

        assert len(errors_received) == 1
        assert errors_received[0]["hook"] == "before_llm_call"
        assert isinstance(errors_received[0]["error"], Exception)

    def test_policy_violation_always_raises_regardless_of_fail_open(self, guard):
        """AgentGuardViolation from a real BLOCK is *never* swallowed."""
        enable_guard(guard, fail_open=True)
        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

    def test_fail_open_false_policy_violation_still_raises(self, guard):
        """AgentGuardViolation is raised even when fail_open=False (not wrapped)."""
        enable_guard(guard, fail_open=False)
        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

    def test_broken_on_error_callback_does_not_bypass_fail_closed(self, guard):
        def broken_callback(**kwargs):
            raise RuntimeError("callback exploded")

        enable_guard(
            guard,
            fail_open=False,
            on_error=broken_callback,
            hooks=["before_llm_call"],
        )

        ctx = self._make_broken_context()

        with pytest.raises(AgentGuardHookError):
            _fire_before_llm(ctx)

    def test_broken_on_violation_callback_does_not_bypass_block(self, guard):
        def broken_callback(**kwargs):
            raise RuntimeError("callback exploded")

        enable_guard(
            guard,
            on_violation=broken_callback,
            hooks=["before_llm_call"],
        )

        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )

        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

    def test_broken_quarantine_handler_does_not_bypass_quarantine(
        self,
        quarantine_guard,
    ):
        def broken_handler(**kwargs):
            raise RuntimeError("quarantine handler exploded")

        enable_guard(
            quarantine_guard,
            quarantine_handler=broken_handler,
            hooks=["before_llm_call"],
        )

        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )

        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)


class TestQuarantineViaEnableGuard:
    """End-to-end: quarantine policy + quarantine_handler through hooks."""

    def test_quarantine_handler_called_via_before_llm(self, quarantine_guard):
        quarantined_items = []

        def qhandler(*, source, content, decision):
            quarantined_items.append(
                {"source": source, "content": content, "action": decision.action}
            )

        adapter = enable_guard(
            quarantine_guard,
            quarantine_handler=qhandler,
            hooks=["before_llm_call"],
        )
        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        _fire_before_llm(ctx)

        assert len(quarantined_items) == 1
        assert quarantined_items[0]["action"] == Action.QUARANTINE
        assert adapter.violations >= 1

    def test_quarantine_handler_called_via_after_tool(self, quarantine_guard):
        quarantined_items = []

        def qhandler(*, source, content, decision):
            quarantined_items.append(content)

        enable_guard(
            quarantine_guard,
            quarantine_handler=qhandler,
            hooks=["after_tool_call"],
        )
        ctx = _make_tool_context(tool_result=PROMPT_INJECTION_TEXT)
        _fire_after_tool(ctx)

        assert len(quarantined_items) == 1


class TestOnViolationViaEnableGuard:
    """Verify the on_violation callback fires for blocks through hooks."""

    def test_on_violation_invoked_on_block(self, guard):
        violations = []

        def violation_recorder(*, source, decision, content):
            violations.append(decision.action)

        enable_guard(guard, on_violation=violation_recorder)
        ctx = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx)

        assert Action.BLOCK in violations


class TestAdapterViolationCounting:
    def test_violations_increment_across_calls(self, guard):
        adapter = enable_guard(guard)

        ctx1 = _make_llm_context(
            messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
        )
        with pytest.raises(AgentGuardViolation):
            _fire_before_llm(ctx1)

        ctx2 = _make_llm_context(response=SECRET_TEXT)
        with pytest.raises(AgentGuardViolation):
            _fire_after_llm(ctx2)

        assert adapter.violations >= 2
