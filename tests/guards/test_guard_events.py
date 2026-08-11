from __future__ import annotations

import pytest

from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.events import (
    Action,
    EventType,
    Severity,
    SourceClass,
)
from qarai_agent_guard.core.schemas.guard import SecurityMode

from .conftest import (
    CARD_PAYLOAD,
    EMAIL_PAYLOAD,
    IBAN_PAYLOAD,
    MULTI_THREAT_PAYLOAD,
    SAFE_PAYLOAD,
)


def test_security_event_callbacks(pii_detector):
    received: list = []
    guard = AgentGuard(detectors=[pii_detector], event_callbacks=[received.append])

    post_received: list = []
    guard.register_callback(post_received.append)

    guard.inspect(key="memory", value=IBAN_PAYLOAD, operation="write", emit_events=True)
    assert len(received) == 1
    assert len(post_received) == 1
    assert received[0].detector == "pii"


def test_register_callback_rejects_non_callable(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    with pytest.raises(TypeError, match="callback must be callable"):
        guard.register_callback("not-callable")


def test_callback_failure_logged_as_event(pii_detector, capsys):
    def bad_callback(event):
        raise RuntimeError("callback exploded")

    guard = AgentGuard(detectors=[pii_detector], event_callbacks=[bad_callback])
    guard.inspect(key="mem", value=IBAN_PAYLOAD, operation="write", emit_events=True)

    captured = capsys.readouterr()
    assert "callback exploded" in captured.err

    cb_events = [e for e in guard.events if e.event_type == EventType.CALLBACK_FAILURE]
    assert len(cb_events) == 1
    assert cb_events[0].severity == Severity.HIGH


def test_request_metadata_attached_to_events(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(
        key="mem",
        value=IBAN_PAYLOAD,
        operation="write",
        emit_events=True,
        request_metadata={"session_id": "sess-amine-0142"},
    )
    assert any(e.metadata.get("session_id") == "sess-amine-0142" for e in guard.events)


def test_event_type_classification(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=IBAN_PAYLOAD, operation="write", emit_events=True)
    detection_events = [e for e in guard.events if e.event_type == EventType.DETECTION]
    assert len(detection_events) == 1


def test_events_not_emitted_by_default(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=IBAN_PAYLOAD, operation="write")
    assert guard.events == []


def test_event_fields_populated_for_detection(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(
        key="mem",
        value=CARD_PAYLOAD,
        operation="write",
        emit_events=True,
        source_class=SourceClass.USER_INPUT,
        request_metadata={"trace_id": "trace-042"},
    )
    event = guard.events[0]
    assert event.detector == "pii"
    assert event.severity == Severity.CRITICAL
    assert event.action == Action.BLOCK
    assert event.key == "mem"
    assert event.operation == "write"
    assert event.source_class == SourceClass.USER_INPUT
    assert event.event_type == EventType.DETECTION
    assert event.metadata["trace_id"] == "trace-042"
    assert event.metadata["hit_count"] == 1


def test_no_events_when_nothing_matches(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=SAFE_PAYLOAD, operation="write", emit_events=True)
    assert guard.events == []


def test_events_emitted_per_detector(multi_detector_guard):
    guard = AgentGuard(detectors=multi_detector_guard.detectors)
    guard.inspect(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write", emit_events=True
    )
    detection_events = [e for e in guard.events if e.event_type == EventType.DETECTION]
    assert {e.detector for e in detection_events} == {
        "pii",
        "secrets",
        "prompt_injection",
    }
    assert all(e.action == Action.BLOCK for e in detection_events)


def test_event_action_reflects_medium_redact(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=IBAN_PAYLOAD, operation="write", emit_events=True)
    event = guard.events[0]
    assert event.severity == Severity.MEDIUM
    assert event.action == Action.REDACT


def test_event_action_reflects_low_warn(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=EMAIL_PAYLOAD, operation="write", emit_events=True)
    event = guard.events[0]
    assert event.severity == Severity.LOW
    assert event.action == Action.WARN


def test_event_serializes_to_dict(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write", emit_events=True)
    payload = guard.events[0].to_dict()
    assert payload["detector"] == "pii"
    assert payload["severity"] == "critical"
    assert payload["action"] == "block"
    assert payload["event_type"] == "detection"
    assert payload["source_class"] == "unknown"
    assert "event_id" in payload
    assert "timestamp" in payload


def test_event_action_in_monitor_mode_is_allow(pii_detector):
    guard = AgentGuard(detectors=[pii_detector], security_mode=SecurityMode.MONITOR)
    guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write", emit_events=True)
    event = guard.events[0]
    assert event.action == Action.ALLOW
    assert event.severity == Severity.CRITICAL
