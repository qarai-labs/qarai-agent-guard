from __future__ import annotations

import httpx
import pytest

from qarai_agent_guard import AgentGuard
from qarai_agent_guard.core.exceptions import PolicyEvaluationError
from qarai_agent_guard.core.schemas import (
    Action,
    EventType,
    ExecutionStrategy,
    FailBehavior,
)

from .conftest import CARD_PAYLOAD, PROMPT_INJECTION_PAYLOAD, SAFE_PAYLOAD


def test_detector_execution_failure_fail_open(crashing_detector_factory):
    guard = AgentGuard(
        detectors=[crashing_detector_factory()],
        fail_behavior=FailBehavior.FAIL_OPEN,
    )
    decision, detections = guard.inspect_with_results(
        key="memory", value="routine note", operation="write", emit_events=True
    )
    assert decision.action == Action.ALLOW
    assert len(detections) == 0
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1
    assert "boom" in sys_events[0].message


def test_detector_execution_failure_fail_closed(crashing_detector_factory):
    guard = AgentGuard(
        detectors=[crashing_detector_factory()],
        fail_behavior=FailBehavior.FAIL_CLOSED,
    )
    decision, _ = guard.inspect_with_results(
        key="memory", value="routine note", operation="write"
    )
    assert decision.action == Action.BLOCK
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1
    assert sys_events[0].action == Action.BLOCK


@pytest.mark.parametrize(
    "fail_behavior,expected_action",
    [
        (FailBehavior.FAIL_OPEN, Action.ALLOW),
        (FailBehavior.FAIL_CLOSED, Action.BLOCK),
    ],
)
def test_detector_execution_failure_parametrized(
    crashing_detector_factory, fail_behavior, expected_action
):
    guard = AgentGuard(
        detectors=[crashing_detector_factory()],
        fail_behavior=fail_behavior,
    )
    decision, _ = guard.inspect_with_results(
        key="memory", value="routine note", operation="write"
    )
    assert decision.action == expected_action


def test_policy_evaluation_failure_fail_open(pii_detector, broken_policy_factory):
    guard = AgentGuard(
        detectors=[pii_detector],
        policy=broken_policy_factory(),
        fail_behavior=FailBehavior.FAIL_OPEN,
    )
    decision, _ = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    policy_events = [
        e for e in guard.events if e.event_type == EventType.POLICY_FAILURE
    ]
    assert len(policy_events) == 1


def test_policy_evaluation_failure_fail_closed(pii_detector, broken_policy_factory):
    guard = AgentGuard(
        detectors=[pii_detector],
        policy=broken_policy_factory(),
        fail_behavior=FailBehavior.FAIL_CLOSED,
    )
    with pytest.raises(PolicyEvaluationError, match="policy engine down"):
        guard.inspect_with_results(key="mem", value=CARD_PAYLOAD, operation="write")
    policy_events = [
        e for e in guard.events if e.event_type == EventType.POLICY_FAILURE
    ]
    assert len(policy_events) == 1


def test_exhaustive_continues_after_detector_failure(
    crashing_detector_factory,
    pii_detector,
):
    guard = AgentGuard(detectors=[crashing_detector_factory(), pii_detector])
    decision, detections = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK
    assert len(detections) == 1
    assert detections[0].detector == "pii"
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1


def test_fail_fast_stops_after_detector_failure(
    crashing_detector_factory,
    pii_detector,
):
    guard = AgentGuard(
        detectors=[crashing_detector_factory(), pii_detector],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    decision, detections = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    assert detections == []
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1


def test_multiple_detector_failures_are_collected(crashing_detector_factory):
    guard = AgentGuard(
        detectors=[
            crashing_detector_factory(name="c1"),
            crashing_detector_factory(name="c2"),
        ]
    )
    decision, _ = guard.inspect_with_results(key="mem", value="x", operation="write")
    assert decision.action == Action.ALLOW
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 2
    assert "c1" in sys_events[0].message
    assert "c2" in sys_events[1].message


# Failures raised by the API model provider


@pytest.mark.parametrize(
    ("status_code", "text", "headers", "expected_message"),
    [
        (503, "service unavailable", None, "503"),
        (429, "slow down", {"retry-after": "20"}, "retry after 20"),
    ],
)
def test_api_failure_fail_open(
    status_code,
    text,
    headers,
    expected_message,
    api_detector,
    api_error_response,
    patched_api_client,
):
    """Allows traffic and emits a system-failure event when failing open."""
    guard = AgentGuard(detectors=[api_detector()], fail_behavior=FailBehavior.FAIL_OPEN)

    with patched_api_client(api_error_response(status_code, text, headers)):
        decision = guard.inspect(
            key="memory",
            value=PROMPT_INJECTION_PAYLOAD,
            operation="write",
            emit_events=True,
        )

    assert decision.action == Action.ALLOW
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1
    assert sys_events[0].action == Action.ALLOW
    assert expected_message in sys_events[0].message


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        ({"choices": [{"message": {"content": "maybe"}}]}, "safe"),
        ({"unexpected": "shape"}, "choices"),
        (
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {"content": None},
                    }
                ]
            },
            "max_tokens",
        ),
    ],
)
def test_api_output_failure_respects_fail_behavior(
    payload,
    expected_message,
    api_detector,
    api_response,
    patched_api_client,
):
    """Treats unusable API answers as detector execution failures."""
    guard = AgentGuard(
        detectors=[api_detector()], fail_behavior=FailBehavior.FAIL_CLOSED
    )

    with patched_api_client(api_response(payload=payload)):
        decision = guard.inspect(
            key="memory",
            value=PROMPT_INJECTION_PAYLOAD,
            operation="write",
        )

    assert decision.action == Action.BLOCK
    assert "api_injection" in decision.reason
    assert expected_message in decision.reason


def test_api_failure_blocks_when_fail_closed(
    api_detector,
    api_error_response,
    patched_api_client,
):
    """Blocks and names the failing detector when configured to fail closed."""
    guard = AgentGuard(
        detectors=[api_detector()], fail_behavior=FailBehavior.FAIL_CLOSED
    )

    with patched_api_client(api_error_response(401, "invalid key")):
        decision = guard.inspect(
            key="memory",
            value=PROMPT_INJECTION_PAYLOAD,
            operation="write",
        )

    assert decision.action == Action.BLOCK
    assert "api_injection" in decision.reason
    assert "401" in decision.reason


def test_api_transport_failure_respects_fail_behavior(
    api_detector,
    patched_api_client,
):
    """Handles a connection error like any other detector execution failure."""
    guard = AgentGuard(detectors=[api_detector()], fail_behavior=FailBehavior.FAIL_OPEN)

    with patched_api_client(side_effect=httpx.ConnectError("refused")):
        decision = guard.inspect(
            key="memory",
            value=PROMPT_INJECTION_PAYLOAD,
            operation="write",
        )

    assert decision.action == Action.ALLOW


def test_api_failure_fail_closed_blocks_regardless_of_payload(
    api_detector,
    api_error_response,
    patched_api_client,
):
    """Blocks on a failing API detector even for a benign payload."""
    guard = AgentGuard(
        detectors=[api_detector()], fail_behavior=FailBehavior.FAIL_CLOSED
    )

    with patched_api_client(api_error_response(500, "boom")):
        decision = guard.inspect(key="memory", value=SAFE_PAYLOAD, operation="write")

    assert decision.action == Action.BLOCK
