from __future__ import annotations

import pytest

from qarai_agent_guard import AgentGuard
from qarai_agent_guard.core.schemas import Action, ExecutionStrategy

from .conftest import (
    CARD_PAYLOAD,
    MULTI_THREAT_PAYLOAD,
    PROMPT_INJECTION_PAYLOAD,
    SAFE_PAYLOAD,
)


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


# Mixed HuggingFace and API detectors


def test_huggingface_and_api_detectors_report_both_matches(
    prompt_injection_detector,
    api_detector,
    api_verdict_response,
    patched_api_client,
):
    """Collects matches from a regex detector and an API model detector."""
    guard = AgentGuard(detectors=[prompt_injection_detector, api_detector()])

    with patched_api_client(api_verdict_response("unsafe")):
        decision, detections = guard.inspect_with_results(
            key="mem", value=PROMPT_INJECTION_PAYLOAD, operation="write"
        )

    assert decision.action == Action.BLOCK
    assert {d.detector for d in detections} == {"prompt_injection", "api_injection"}


def test_huggingface_match_blocks_even_when_the_api_verdict_is_safe(
    prompt_injection_detector,
    api_detector,
    api_verdict_response,
    patched_api_client,
):
    """Keeps the regex decision when the API reports no issue."""
    guard = AgentGuard(detectors=[prompt_injection_detector, api_detector()])

    with patched_api_client(api_verdict_response("safe")):
        decision, detections = guard.inspect_with_results(
            key="mem", value=PROMPT_INJECTION_PAYLOAD, operation="write"
        )

    assert decision.action == Action.BLOCK
    assert [d.detector for d in detections] == ["prompt_injection"]


def test_api_match_blocks_a_benign_payload_for_the_regex_detector(
    prompt_injection_detector,
    api_detector,
    api_verdict_response,
    patched_api_client,
):
    """Blocks a benign payload when only the API model detects an issue."""
    guard = AgentGuard(detectors=[prompt_injection_detector, api_detector()])

    with patched_api_client(api_verdict_response("unsafe")):
        decision, detections = guard.inspect_with_results(
            key="mem", value=SAFE_PAYLOAD, operation="write"
        )

    assert decision.action == Action.BLOCK
    assert [d.detector for d in detections] == ["api_injection"]


def test_fail_fast_stops_on_the_huggingface_match(
    prompt_injection_detector,
    api_detector,
    api_verdict_response,
    patched_api_client,
):
    """Skips the API call when a regex detector already matched."""
    guard = AgentGuard(
        detectors=[prompt_injection_detector, api_detector()],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )

    with patched_api_client(api_verdict_response("safe")) as instance:
        decision, detections = guard.inspect_with_results(
            key="mem", value=PROMPT_INJECTION_PAYLOAD, operation="write"
        )

    assert decision.action == Action.BLOCK
    assert [d.detector for d in detections] == ["prompt_injection"]
    instance.post.assert_not_called()


def test_disabled_api_detector_is_skipped(
    prompt_injection_detector,
    api_detector,
    api_verdict_response,
    patched_api_client,
):
    """Keeps the remaining detectors active when the API detector is disabled."""
    guard = AgentGuard(detectors=[prompt_injection_detector, api_detector()])
    guard.disable_detector("api_injection")

    with patched_api_client(api_verdict_response("unsafe")) as instance:
        decision, detections = guard.inspect_with_results(
            key="mem", value=SAFE_PAYLOAD, operation="write"
        )

    assert decision.action == Action.ALLOW
    assert detections == []
    instance.post.assert_not_called()
