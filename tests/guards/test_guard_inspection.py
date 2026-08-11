from __future__ import annotations

import pytest

from qarai_agent_guard.core.detectors.detector import Detector
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.events import Action, SourceClass

from .conftest import (
    AR_PROMPT_INJECTION_PAYLOAD,
    AR_SAFE_PAYLOAD,
    CARD_PAYLOAD,
    CUSTOM_HIGH_PAYLOAD,
    CUSTOM_MEDIUM_PAYLOAD,
    CUSTOM_SAFE_PAYLOAD,
    EMAIL_PAYLOAD,
    FR_PROMPT_INJECTION_PAYLOAD,
    FR_SAFE_PAYLOAD,
    IBAN_PAYLOAD,
    MULTI_THREAT_PAYLOAD,
    PROMPT_INJECTION_PAYLOAD,
    SAFE_PAYLOAD,
    SECRET_PAYLOAD,
)


def test_agent_guard_blocks_prompt_injection(agent_guard):
    decision = agent_guard.inspect(
        key="memory", value=PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


def test_agent_guard_allows_safe_content(agent_guard):
    decision = agent_guard.inspect(key="memory", value=SAFE_PAYLOAD, operation="write")
    assert decision.action == Action.ALLOW


def test_inspect_with_results_returns_detections(agent_guard):
    decision, detections = agent_guard.inspect_with_results(
        key="memory", value=PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK
    assert len(detections) == 1
    assert detections[0].detector == "prompt_injection"


def test_check_convenience_wrapper_emits_events(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    decision, detections = guard.check(
        key="memory", value=CARD_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK
    assert guard.events


def test_fail_fast_stops_after_first_match(pii_detector, secrets_detector):
    call_log: list[str] = []

    class LoggingWrapper(Detector):
        def __init__(self, inner: Detector) -> None:
            self._inner = inner
            self.name = inner.name

        def inspect(self, key, value, *, operation):
            call_log.append(self.name)
            return self._inner.inspect(key=key, value=value, operation=operation)

        def redact(self, value, entities=None):
            return self._inner.redact(value, entities=entities)

    logging_pii = LoggingWrapper(pii_detector)
    logging_secrets = LoggingWrapper(secrets_detector)

    from qarai_agent_guard.core.schemas.guard import ExecutionStrategy

    guard = AgentGuard(
        detectors=[logging_pii, logging_secrets],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    guard.inspect_with_results(key="mem", value=CARD_PAYLOAD, operation="write")
    assert call_log == ["pii"]


def test_key_must_be_non_empty_string(agent_guard):
    with pytest.raises(ValueError, match="key must not be empty"):
        agent_guard.inspect(key="   ", value=SAFE_PAYLOAD, operation="write")


def test_operation_must_be_non_empty_string(agent_guard):
    with pytest.raises(ValueError, match="operation must not be empty"):
        agent_guard.inspect(key="memory", value=SAFE_PAYLOAD, operation="")


def test_source_class_must_be_enum_member(agent_guard):
    import pytest

    with pytest.raises(TypeError, match="source_class must be SourceClass"):
        agent_guard.inspect(
            key="memory", value=SAFE_PAYLOAD, operation="write", source_class="user"
        )


# Multiple detectors


def test_multi_detector_guard_blocks_combined_threat(multi_detector_guard):
    decision = multi_detector_guard.inspect(
        key="memory", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


def test_multi_detector_exhaustive_collects_all_matches(multi_detector_guard):
    decision, detections = multi_detector_guard.inspect_with_results(
        key="memory", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert {d.detector for d in detections} == {"pii", "secrets", "prompt_injection"}
    assert decision.action == Action.BLOCK


def test_multi_detector_guard_allows_safe_content(multi_detector_guard):
    decision = multi_detector_guard.inspect(
        key="memory", value=SAFE_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW


# Language-specific prompt-injection inspection


def test_french_prompt_injection_blocked(fr_prompt_injection_detector):
    guard = AgentGuard(detectors=[fr_prompt_injection_detector])
    decision = guard.inspect(
        key="memory", value=FR_PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


def test_french_safe_content_allowed(fr_prompt_injection_detector):
    guard = AgentGuard(detectors=[fr_prompt_injection_detector])
    decision = guard.inspect(key="memory", value=FR_SAFE_PAYLOAD, operation="write")
    assert decision.action == Action.ALLOW


def test_arabic_prompt_injection_blocked(ar_prompt_injection_detector):
    guard = AgentGuard(detectors=[ar_prompt_injection_detector])
    decision = guard.inspect(
        key="memory", value=AR_PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


def test_arabic_safe_content_allowed(ar_prompt_injection_detector):
    guard = AgentGuard(detectors=[ar_prompt_injection_detector])
    decision = guard.inspect(key="memory", value=AR_SAFE_PAYLOAD, operation="write")
    assert decision.action == Action.ALLOW


@pytest.mark.parametrize(
    "detector_fixture,payload,expected_action",
    [
        ("prompt_injection_detector", FR_PROMPT_INJECTION_PAYLOAD, Action.ALLOW),
        ("prompt_injection_detector", AR_PROMPT_INJECTION_PAYLOAD, Action.ALLOW),
        ("fr_prompt_injection_detector", PROMPT_INJECTION_PAYLOAD, Action.ALLOW),
        ("ar_prompt_injection_detector", PROMPT_INJECTION_PAYLOAD, Action.ALLOW),
    ],
)
def test_prompt_injection_rules_are_language_specific(
    request,
    detector_fixture,
    payload,
    expected_action,
):
    detector = request.getfixturevalue(detector_fixture)
    guard = AgentGuard(detectors=[detector])
    decision = guard.inspect(key="memory", value=payload, operation="write")
    assert decision.action == expected_action


# Custom patterns without default rules


def test_custom_pattern_medium_severity_redacts(custom_pattern_detector):
    guard = AgentGuard(detectors=[custom_pattern_detector])
    decision = guard.inspect(
        key="memory", value=CUSTOM_MEDIUM_PAYLOAD, operation="write"
    )
    assert decision.action == Action.REDACT


def test_custom_pattern_high_severity_blocks(custom_pattern_detector):
    guard = AgentGuard(detectors=[custom_pattern_detector])
    decision = guard.inspect(key="memory", value=CUSTOM_HIGH_PAYLOAD, operation="write")
    assert decision.action == Action.BLOCK


def test_custom_pattern_safe_content_allows(custom_pattern_detector):
    guard = AgentGuard(detectors=[custom_pattern_detector])
    decision = guard.inspect(key="memory", value=CUSTOM_SAFE_PAYLOAD, operation="write")
    assert decision.action == Action.ALLOW


# Real examples mapped to expected policy actions


@pytest.mark.parametrize(
    "detector_fixture,payload,expected_action",
    [
        ("pii_detector", SAFE_PAYLOAD, Action.ALLOW),
        ("pii_detector", EMAIL_PAYLOAD, Action.WARN),
        ("pii_detector", IBAN_PAYLOAD, Action.REDACT),
        ("pii_detector", CARD_PAYLOAD, Action.BLOCK),
        ("secrets_detector", SECRET_PAYLOAD, Action.BLOCK),
        ("prompt_injection_detector", PROMPT_INJECTION_PAYLOAD, Action.BLOCK),
    ],
)
def test_real_examples_map_to_expected_actions(
    request,
    detector_fixture,
    payload,
    expected_action,
):
    detector = request.getfixturevalue(detector_fixture)
    guard = AgentGuard(detectors=[detector])
    decision = guard.inspect(key="memory", value=payload, operation="write")
    assert decision.action == expected_action


# Input handling


def test_inspect_accepts_source_class_enum(agent_guard):
    decision = agent_guard.inspect(
        key="memory",
        value=PROMPT_INJECTION_PAYLOAD,
        operation="write",
        source_class=SourceClass.USER_INPUT,
    )
    assert decision.action == Action.BLOCK


def test_inspect_empty_value_allows(agent_guard):
    decision = agent_guard.inspect(key="memory", value="", operation="write")
    assert decision.action == Action.ALLOW


@pytest.mark.parametrize("operation", ["write", "read", "delete", "tool_call"])
def test_inspect_supports_operations(agent_guard, operation):
    decision = agent_guard.inspect(
        key="memory", value=PROMPT_INJECTION_PAYLOAD, operation=operation
    )
    assert decision.action == Action.BLOCK


def test_inspect_stringifies_structured_values(agent_guard):
    decision = agent_guard.inspect(
        key="memory",
        value={"messages": [{"role": "user", "content": PROMPT_INJECTION_PAYLOAD}]},
        operation="write",
    )
    assert decision.action == Action.BLOCK
