from __future__ import annotations

import pytest

from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.events import Action
from qarai_agent_guard.core.schemas.guard import ExecutionStrategy

from .conftest import CARD_PAYLOAD, MULTI_THREAT_PAYLOAD, SAFE_PAYLOAD


def test_exhaustive_runs_all_detectors(multi_detector_guard):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        execution_strategy=ExecutionStrategy.EXHAUSTIVE,
    )
    _, detections = guard.inspect_with_results(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert {d.detector for d in detections} == {"pii", "secrets", "prompt_injection"}


def test_fail_fast_stops_after_first_match(multi_detector_guard):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    _, detections = guard.inspect_with_results(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert len(detections) == 1
    assert detections[0].detector == "pii"


@pytest.mark.parametrize(
    "strategy",
    [ExecutionStrategy.EXHAUSTIVE, ExecutionStrategy.FAIL_FAST],
)
def test_both_strategies_reach_same_decision(multi_detector_guard, strategy):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        execution_strategy=strategy,
    )
    decision = guard.inspect(key="mem", value=MULTI_THREAT_PAYLOAD, operation="write")
    assert decision.action == Action.BLOCK


@pytest.mark.parametrize(
    "strategy",
    [ExecutionStrategy.EXHAUSTIVE, ExecutionStrategy.FAIL_FAST],
)
def test_safe_payload_produces_no_detections(multi_detector_guard, strategy):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        execution_strategy=strategy,
    )
    decision, detections = guard.inspect_with_results(
        key="mem", value=SAFE_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    assert detections == []


def test_fail_fast_returns_single_detection_for_single_threat(pii_detector):
    guard = AgentGuard(
        detectors=[pii_detector],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    _, detections = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert len(detections) == 1


def test_disabled_detector_skipped_in_execution(multi_detector_guard):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        execution_strategy=ExecutionStrategy.EXHAUSTIVE,
    )
    guard.disable_detector("secrets")
    _, detections = guard.inspect_with_results(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert {d.detector for d in detections} == {"pii", "prompt_injection"}


def test_fail_fast_with_disabled_first_detector(pii_detector, secrets_detector):
    """Fail-fast stops at the first *enabled* detector that matches."""
    guard = AgentGuard(
        detectors=[pii_detector, secrets_detector],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    guard.disable_detector("pii")
    _, detections = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert detections == []
