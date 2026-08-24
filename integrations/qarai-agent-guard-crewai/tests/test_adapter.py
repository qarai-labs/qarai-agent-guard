from __future__ import annotations

import pytest
from qarai_agent_guard import Action, PolicyDecision

from qarai_agent_guard_crewai.agent_guard_adapter import AgentGuardAdapter
from qarai_agent_guard_crewai.exceptions import AgentGuardViolation

from .conftest import CLEAN_TEXT, PII_TEXT, PROMPT_INJECTION_TEXT, SECRET_TEXT


def _check_and_enforce(adapter: AgentGuardAdapter, text: str, source: str = "test"):
    """Run the guard's check pipeline, then enforce the decision."""
    decision, detections = adapter.guard.check(
        key="test_key",
        value=text,
        operation="write",
    )
    return adapter.enforce(
        decision=decision,
        content=text,
        detections=detections,
        source=source,
    )


class TestEnforceAllow:
    def test_enforce_allow_clean_content(self, guard):
        adapter = AgentGuardAdapter(guard)
        result = _check_and_enforce(adapter, CLEAN_TEXT)

        assert result.action == Action.ALLOW
        assert result.content == CLEAN_TEXT
        assert result.redacted is False
        assert adapter.violations == 0

    def test_enforce_allow_does_not_increment_violations(self, guard):
        adapter = AgentGuardAdapter(guard)
        _check_and_enforce(adapter, CLEAN_TEXT)
        _check_and_enforce(adapter, "Another safe sentence.")
        assert adapter.violations == 0


class TestEnforceWarn:
    def test_enforce_warn_returns_original_content(self, guard):
        """Force a WARN decision and verify content is unchanged."""
        adapter = AgentGuardAdapter(guard)
        decision = PolicyDecision(action=Action.WARN, reason="low severity match")
        result = adapter.enforce(
            decision=decision,
            content=CLEAN_TEXT,
            detections=None,
            source="test.warn",
        )
        assert result.action == Action.WARN
        assert result.content == CLEAN_TEXT
        assert adapter.violations == 0


class TestEnforceBlock:
    def test_enforce_block_raises_on_prompt_injection(self, guard):
        adapter = AgentGuardAdapter(guard)
        with pytest.raises(AgentGuardViolation, match="blocked"):
            _check_and_enforce(adapter, PROMPT_INJECTION_TEXT)

    def test_enforce_block_increments_violation_count(self, guard):
        adapter = AgentGuardAdapter(guard)
        try:
            _check_and_enforce(adapter, PROMPT_INJECTION_TEXT)
        except AgentGuardViolation:
            pass
        assert adapter.violations == 1

    def test_enforce_block_on_secrets(self, guard):
        adapter = AgentGuardAdapter(guard)
        with pytest.raises(AgentGuardViolation):
            _check_and_enforce(adapter, SECRET_TEXT)


class TestEnforceRedact:
    def test_enforce_redact_pii_sanitises_content(self, guard):
        adapter = AgentGuardAdapter(guard)
        result = _check_and_enforce(adapter, PII_TEXT)

        assert result.action == Action.REDACT
        assert result.redacted is True
        assert "GB29NWBK60161331926819" not in result.content
        assert adapter.violations == 0

    def test_enforce_redact_without_detections_passes_through(self, guard):
        """REDACT decision but no detections → content unchanged."""
        adapter = AgentGuardAdapter(guard)
        decision = PolicyDecision(action=Action.REDACT, reason="medium match")
        result = adapter.enforce(
            decision=decision,
            content=CLEAN_TEXT,
            detections=[],
            source="test.redact.empty",
        )
        assert result.content == CLEAN_TEXT
        assert result.action == Action.REDACT


class TestEnforceQuarantine:
    def test_quarantine_handler_called(self, quarantine_guard):
        calls = []

        def handler(*, source, content, decision):
            calls.append({"source": source, "content": content, "decision": decision})

        adapter = AgentGuardAdapter(quarantine_guard, quarantine_handler=handler)
        decision, detections = quarantine_guard.check(
            key="test_key",
            value=PROMPT_INJECTION_TEXT,
            operation="write",
        )
        assert decision.action == Action.QUARANTINE

        adapter.enforce(
            decision=decision,
            content=PROMPT_INJECTION_TEXT,
            detections=detections,
            source="test.quarantine",
        )
        assert len(calls) == 1
        assert calls[0]["source"] == "test.quarantine"
        assert adapter.violations == 1

    def test_quarantine_handler_raises_produces_violation(self, quarantine_guard):
        def bad_handler(*, source, content, decision):
            raise RuntimeError("handler boom")

        adapter = AgentGuardAdapter(quarantine_guard, quarantine_handler=bad_handler)
        decision, detections = quarantine_guard.check(
            key="test_key",
            value=PROMPT_INJECTION_TEXT,
            operation="write",
        )
        with pytest.raises(AgentGuardViolation, match="quarantined"):
            adapter.enforce(
                decision=decision,
                content=PROMPT_INJECTION_TEXT,
                detections=detections,
                source="test.quarantine.fail",
            )

    def test_quarantine_no_handler_falls_through(self, quarantine_guard):
        """No quarantine_handler set → falls through to unrecognized-action block."""
        adapter = AgentGuardAdapter(quarantine_guard, quarantine_handler=None)
        decision, detections = quarantine_guard.check(
            key="test_key",
            value=PROMPT_INJECTION_TEXT,
            operation="write",
        )

        with pytest.raises(AgentGuardViolation, match="quarantined"):
            adapter.enforce(
                decision=decision,
                content=PROMPT_INJECTION_TEXT,
                detections=detections,
                source="test.quarantine.nohandler",
            )


class TestOnViolationCallback:
    def test_on_violation_receives_context(self, guard):
        calls = []

        def recorder(*, source, decision, content):
            calls.append({"source": source, "decision": decision, "content": content})

        adapter = AgentGuardAdapter(guard, on_violation=recorder)
        with pytest.raises(AgentGuardViolation):
            _check_and_enforce(adapter, PROMPT_INJECTION_TEXT, source="callback.test")

        assert len(calls) == 1
        assert calls[0]["source"] == "callback.test"
        assert calls[0]["decision"].action == Action.BLOCK
        assert calls[0]["content"] == PROMPT_INJECTION_TEXT

    def test_on_violation_exception_is_swallowed(self, guard):
        """A crashing on_violation must not prevent the BLOCK from being raised."""

        def crasher(*, source, decision, content):
            raise RuntimeError("callback exploded")

        adapter = AgentGuardAdapter(guard, on_violation=crasher)
        with pytest.raises(AgentGuardViolation):
            _check_and_enforce(adapter, PROMPT_INJECTION_TEXT)
