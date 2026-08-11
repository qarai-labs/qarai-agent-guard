from __future__ import annotations

import pytest

from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.events import Action
from qarai_agent_guard.core.schemas.guard import SecurityMode

from .conftest import (
    CARD_PAYLOAD,
    EMAIL_PAYLOAD,
    IBAN_PAYLOAD,
    MULTI_THREAT_PAYLOAD,
)


def test_monitor_mode_does_not_block(pii_detector):
    guard = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.MONITOR)
    decision = guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write")
    assert decision.action == Action.ALLOW
    assert "[MONITOR]" in decision.reason


def test_enforce_mode_does_block(pii_detector):
    guard = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.ENFORCE)
    decision = guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write")
    assert decision.action == Action.BLOCK


@pytest.mark.parametrize(
    "payload,enforce_action",
    [
        (CARD_PAYLOAD, Action.BLOCK),
        (IBAN_PAYLOAD, Action.REDACT),
    ],
)
def test_monitor_mode_converts_block_and_redact_to_allow(
    pii_detector,
    payload,
    enforce_action,
):
    enforce = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.ENFORCE)
    assert (
        enforce.inspect(key="mem", value=payload, operation="write").action
        == enforce_action
    )

    monitor = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.MONITOR)
    decision = monitor.inspect(key="mem", value=payload, operation="write")
    assert decision.action == Action.ALLOW
    assert "[MONITOR]" in decision.reason


def test_monitor_mode_keeps_warn_action(pii_detector):
    monitor = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.MONITOR)
    decision = monitor.inspect(key="mem", value=EMAIL_PAYLOAD, operation="write")
    assert decision.action == Action.WARN
    assert "[MONITOR]" not in decision.reason


def test_monitor_mode_still_returns_detections(pii_detector):
    guard = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.MONITOR)
    decision, detections = guard.inspect_with_results(
        key="mem", value=CARD_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    assert len(detections) == 1


def test_monitor_mode_multi_detector(multi_detector_guard):
    guard = AgentGuard(
        detectors=multi_detector_guard.detectors,
        security_mode=SecurityMode.MONITOR,
    )
    decision, detections = guard.inspect_with_results(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    assert {d.detector for d in detections} == {"pii", "secrets", "prompt_injection"}
