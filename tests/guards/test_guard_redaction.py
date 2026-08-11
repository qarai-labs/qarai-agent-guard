from __future__ import annotations

import pytest

from qarai_agent_guard.core.exceptions import RedactionError
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.detection import DetectionResult, Match
from qarai_agent_guard.core.schemas.events import Severity
from qarai_agent_guard.core.schemas.guard import FailBehavior
from qarai_agent_guard.core.schemas.models import ModelDetectionResult

from .conftest import (
    AWS_KEY_SAMPLE,
    EMAIL_PAYLOAD,
    EMAIL_SAMPLE,
    IBAN_PAYLOAD,
    IBAN_SAMPLE,
    SAFE_PAYLOAD,
    SECRET_PAYLOAD,
)


def test_agent_guard_redacts_medium_severity(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    redacted = guard.apply_redactions(IBAN_PAYLOAD)
    assert "[REDACTED:iban]" in redacted
    assert IBAN_SAMPLE not in redacted


def test_multi_detector_redaction_fail_open(pii_detector, bad_redact_detector_factory):
    guard = AgentGuard(
        detectors=[pii_detector, bad_redact_detector_factory()],
        fail_behavior=FailBehavior.FAIL_OPEN,
    )
    result = guard.apply_redactions(IBAN_PAYLOAD)
    assert "[REDACTED:iban]" in result
    sys_events = [e for e in guard.events if e.event_type.name == "SYSTEM_FAILURE"]
    assert len(sys_events) == 1


def test_multi_detector_redaction_fail_closed(
    pii_detector,
    bad_redact_detector_factory,
):
    guard = AgentGuard(
        detectors=[pii_detector, bad_redact_detector_factory()],
        fail_behavior=FailBehavior.FAIL_CLOSED,
    )
    with pytest.raises(RedactionError, match="redact boom"):
        guard.apply_redactions(IBAN_PAYLOAD)


def test_selective_redaction_by_severity(pii_detector):
    """Only detectors whose highest match meets the severity threshold redact."""
    guard = AgentGuard(detectors=[pii_detector])

    detections = [
        DetectionResult(
            detector=pii_detector.name,
            matched=True,
            matches=[Match("iban", "IBAN", "medium", IBAN_SAMPLE)],
        )
    ]

    # Threshold = HIGH -> the medium-severity IBAN match should be skipped.
    redacted_no_op = guard.apply_redactions(
        IBAN_PAYLOAD,
        severity_threshold=Severity.HIGH,
        detections=detections,
    )
    assert "[REDACTED:iban]" not in redacted_no_op

    # Threshold = MEDIUM -> the IBAN detector should run.
    redacted = guard.apply_redactions(
        IBAN_PAYLOAD,
        severity_threshold=Severity.MEDIUM,
        detections=detections,
    )
    assert "[REDACTED:iban]" in redacted


def test_disabled_detector_is_skipped_during_redaction(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.disable_detector(pii_detector.name)
    redacted = guard.apply_redactions(IBAN_PAYLOAD)
    assert redacted == IBAN_PAYLOAD


def test_guard_redacts_medium_iban_payload(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    redacted = guard.apply_redactions(IBAN_PAYLOAD)
    assert "[REDACTED:iban]" in redacted
    assert IBAN_SAMPLE not in redacted


def test_guard_redacts_low_severity_email(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    redacted = guard.apply_redactions(EMAIL_PAYLOAD)
    assert "[REDACTED:email]" in redacted
    assert EMAIL_SAMPLE not in redacted


def test_secrets_detector_redacts_aws_key(secrets_detector):
    guard = AgentGuard(detectors=[secrets_detector])
    redacted = guard.apply_redactions(SECRET_PAYLOAD)
    assert "[REDACTED:aws_access_key]" in redacted
    assert AWS_KEY_SAMPLE not in redacted


def test_multi_detector_redaction_combines_transforms(pii_detector, secrets_detector):
    guard = AgentGuard(detectors=[pii_detector, secrets_detector])
    payload = f"{IBAN_PAYLOAD} plus {SECRET_PAYLOAD}"
    redacted = guard.apply_redactions(payload)
    assert "[REDACTED:iban]" in redacted
    assert "[REDACTED:aws_access_key]" in redacted
    assert IBAN_SAMPLE not in redacted
    assert AWS_KEY_SAMPLE not in redacted


def test_redaction_with_model_entities(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    model_result = ModelDetectionResult(
        detected=True,
        score=0.99,
        severity=Severity.HIGH,
        entities=[{"start": 5, "end": 10, "entity_group": "PERSON"}],
    )
    detections = [
        DetectionResult(
            detector=pii_detector.name,
            matched=True,
            message="model detection",
            model_detection_result=model_result,
        )
    ]
    redacted = guard.apply_redactions("Name Alice please", detections=detections)
    assert "Alice" not in redacted
    assert "[REDACTED:PERSON]" in redacted


def test_redaction_returns_input_unchanged_when_no_rules_match(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    assert guard.apply_redactions(SAFE_PAYLOAD) == SAFE_PAYLOAD
