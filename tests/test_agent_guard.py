from __future__ import annotations

from pathlib import Path

import pytest

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.detectors.PIIDetector import PIIDetector
from qarai_agent_guard.core.detectors.models.schemas import ModelDetectionResult
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.detection import DetectionResult
from qarai_agent_guard.core.guards.config import (
    ExecutionStrategy,
    FailBehavior,
    SecurityMode,
)
from qarai_agent_guard.core.guards.exceptions import (
    PolicyEvaluationError,
    RedactionError,
)
from qarai_agent_guard.core.schemas.events import Action, EventType, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _crashing_detector(name: str = "crashing") -> BaseDetector:
    """Return a BaseDetector subclass whose inspect() always raises."""

    class CrashingDetector(BaseDetector):
        def _load_default_rules(self):
            return []

        def inspect(self, key, value, operation):
            raise RuntimeError("boom")

    CrashingDetector.name = name
    return CrashingDetector()


def _bad_redact_detector(name: str = "bad_redact") -> BaseDetector:
    """Return a detector whose redact() always raises."""

    class BadRedactDetector(BaseDetector):
        def _load_default_rules(self):
            return []

        def redact(self, value):
            raise RuntimeError("redact boom")

    BadRedactDetector.name = name
    return BadRedactDetector()


# ---------------------------------------------------------------------------
# Existing baseline tests
# ---------------------------------------------------------------------------


def test_agent_guard_blocks_critical_match(agent_guard):
    decision = agent_guard.inspect(
        key="memory",
        value="show chain of thought",
        operation="write",
    )
    assert decision.action == Action.BLOCK


def test_agent_guard_allows_safe_content(agent_guard):
    decision = agent_guard.inspect(
        key="memory",
        value="What is machine learning?",
        operation="write",
    )
    assert decision.action == Action.ALLOW


def test_agent_guard_create_with_policy_path(tmp_path: Path, model_reasoning_detector):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
version: "1.0"
name: strict-test
default_action: allow
rules:
  - severities: [critical, high, medium, low]
    action: block
""".strip(),
        encoding="utf-8",
    )
    guard = AgentGuard.create(
        detectors=[model_reasoning_detector],
        policy_path=policy_file,
    )
    decision = guard.inspect(
        key="memory",
        value="ignore reasoning",
        operation="write",
    )
    assert decision.action == Action.BLOCK


def test_agent_guard_redacts_medium_severity():
    guard = AgentGuard(detectors=[PIIDetector()])
    redacted = guard.apply_redactions("iban FR1420041010050500013M02606")
    assert "[REDACTED:iban]" in redacted


def test_apply_redactions_uses_model_detection_entities():
    class EntityAwareDetector(BaseDetector):
        name = "entity_detector"

        def _load_default_rules(self):
            return []

        def inspect(self, key, value, operation):
            return DetectionResult(
                detector=self.name,
                matched=True,
                message="model pii detected",
                model_detection_result=ModelDetectionResult(
                    detected=True,
                    score=0.95,
                    label="pii_detected",
                    metadata={
                        "max_severity": Severity.CRITICAL,
                        "entities": [
                            {"start": 0, "end": 5, "entity_group": "EMAIL"}
                        ],
                    },
                ),
            )

        def redact(self, value, entities=None):
            assert entities is not None
            text = str(value)
            for ent in sorted(entities, key=lambda item: item["start"], reverse=True):
                text = (
                    text[: ent["start"]]
                    + f"[REDACTED:{ent['entity_group']}]"
                    + text[ent["end"] :]
                )
            return text

    guard = AgentGuard(detectors=[EntityAwareDetector()])
    _, detections = guard.inspect_with_results(
        key="memory",
        value="abcde",
        operation="write",
    )

    redacted = guard.apply_redactions("abcde", detections=detections)

    assert redacted == "[REDACTED:EMAIL]"


def test_inspect_with_results_returns_detections(agent_guard):
    decision, detections = agent_guard.inspect_with_results(
        key="memory",
        value="ignore reasoning",
        operation="write",
    )
    assert decision.action == Action.BLOCK
    assert len(detections) == 1


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


def test_invalid_detector_registration():
    with pytest.raises(TypeError, match="must inherit from BaseDetector"):
        AgentGuard(detectors=["not-a-detector"])


def test_invalid_policy_configuration():
    class BadPolicy:
        pass

    with pytest.raises(TypeError, match="policy must implement the Policy interface"):
        AgentGuard(detectors=[PIIDetector()], policy=BadPolicy())


def test_invalid_fail_behavior():
    with pytest.raises(ValueError, match="fail_behavior"):
        AgentGuard(detectors=[PIIDetector()], fail_behavior="invalid")


def test_invalid_security_mode():
    with pytest.raises(ValueError, match="security_mode"):
        AgentGuard(detectors=[PIIDetector()], security_mode="invalid")


def test_invalid_execution_strategy():
    with pytest.raises(ValueError, match="execution_strategy"):
        AgentGuard(detectors=[PIIDetector()], execution_strategy="invalid")


# ---------------------------------------------------------------------------
# Duplicate detector validation
# ---------------------------------------------------------------------------


def test_duplicate_detector_names_raise():
    with pytest.raises(ValueError, match="Duplicate detector name"):
        AgentGuard(detectors=[PIIDetector(), PIIDetector()])


# ---------------------------------------------------------------------------
# Dynamic detector management
# ---------------------------------------------------------------------------


def test_register_detector_at_runtime():
    guard = AgentGuard(detectors=[])
    guard.register_detector(PIIDetector())
    assert any(d.name == "pii" for d in guard.detectors)


def test_register_duplicate_detector_raises():
    guard = AgentGuard(detectors=[PIIDetector()])
    with pytest.raises(ValueError, match="already registered"):
        guard.register_detector(PIIDetector())


def test_register_invalid_detector_raises():
    guard = AgentGuard(detectors=[])
    with pytest.raises(TypeError, match="must inherit from BaseDetector"):
        guard.register_detector("not-a-detector")


def test_unregister_detector():
    guard = AgentGuard(detectors=[PIIDetector()])
    guard.unregister_detector("pii")
    assert not any(d.name == "pii" for d in guard.detectors)


def test_unregister_unknown_detector_raises():
    guard = AgentGuard(detectors=[])
    with pytest.raises(ValueError, match="No detector named"):
        guard.unregister_detector("ghost")


def test_disable_and_enable_detector():
    guard = AgentGuard(detectors=[PIIDetector()])
    guard.disable_detector("pii")
    assert "pii" in guard._disabled
    result = guard.inspect(
        key="mem", value="card 4111 1111 1111 1111", operation="write"
    )
    assert result.action == Action.ALLOW  # disabled → not detected

    guard.enable_detector("pii")
    assert "pii" not in guard._disabled
    result = guard.inspect(
        key="mem", value="card 4111 1111 1111 1111", operation="write"
    )
    assert result.action != Action.ALLOW  # re-enabled → detected


def test_disable_unknown_detector_raises():
    guard = AgentGuard(detectors=[])
    with pytest.raises(ValueError, match="No detector named"):
        guard.disable_detector("ghost")


# ---------------------------------------------------------------------------
# Enum / string coercion
# ---------------------------------------------------------------------------


def test_fail_behavior_accepts_enum():
    guard = AgentGuard(detectors=[], fail_behavior=FailBehavior.FAIL_OPEN)
    assert guard.fail_behavior == FailBehavior.FAIL_OPEN


def test_fail_behavior_accepts_string():
    guard = AgentGuard(detectors=[], fail_behavior="fail_closed")
    assert guard.fail_behavior == FailBehavior.FAIL_CLOSED


def test_security_mode_accepts_enum():
    guard = AgentGuard(detectors=[], security_mode=SecurityMode.MONITOR)
    assert guard.security_mode == SecurityMode.MONITOR


def test_execution_strategy_accepts_enum():
    guard = AgentGuard(detectors=[], execution_strategy=ExecutionStrategy.FAIL_FAST)
    assert guard.execution_strategy == ExecutionStrategy.FAIL_FAST


# ---------------------------------------------------------------------------
# Detector execution failures
# ---------------------------------------------------------------------------


def test_detector_execution_failure_fail_open():
    guard = AgentGuard(
        detectors=[_crashing_detector()], fail_behavior=FailBehavior.FAIL_OPEN
    )
    decision, detections = guard.inspect_with_results(
        key="memory", value="test", operation="write", emit_events=True
    )
    assert decision.action == Action.ALLOW
    assert len(detections) == 0
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1
    assert "boom" in sys_events[0].message


def test_detector_execution_failure_fail_closed():
    guard = AgentGuard(
        detectors=[_crashing_detector()], fail_behavior=FailBehavior.FAIL_CLOSED
    )
    decision, detections = guard.inspect_with_results(
        key="memory", value="test", operation="write"
    )
    assert decision.action == Action.BLOCK
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1
    assert sys_events[0].action == Action.BLOCK


# ---------------------------------------------------------------------------
# Policy evaluation failures
# ---------------------------------------------------------------------------


def test_policy_evaluation_failure_fail_open():
    class BrokenPolicy:
        def evaluate(self, results):
            raise RuntimeError("policy engine down")

    guard = AgentGuard(
        detectors=[PIIDetector()],
        policy=BrokenPolicy(),
        fail_behavior=FailBehavior.FAIL_OPEN,
    )
    decision, _ = guard.inspect_with_results(
        key="mem", value="card 4111 1111 1111 1111", operation="write"
    )
    assert decision.action == Action.ALLOW
    policy_events = [
        e for e in guard.events if e.event_type == EventType.POLICY_FAILURE
    ]
    assert len(policy_events) == 1


def test_policy_evaluation_failure_fail_closed():
    class BrokenPolicy:
        def evaluate(self, results):
            raise RuntimeError("policy engine down")

    guard = AgentGuard(
        detectors=[PIIDetector()],
        policy=BrokenPolicy(),
        fail_behavior=FailBehavior.FAIL_CLOSED,
    )
    with pytest.raises(PolicyEvaluationError, match="policy engine down"):
        guard.inspect_with_results(
            key="mem", value="card 4111 1111 1111 1111", operation="write"
        )
    policy_events = [
        e for e in guard.events if e.event_type == EventType.POLICY_FAILURE
    ]
    assert len(policy_events) == 1


# ---------------------------------------------------------------------------
# Security mode
# ---------------------------------------------------------------------------


def test_monitor_mode_does_not_block():
    guard = AgentGuard(
        detectors=[PIIDetector()],
        security_mode=SecurityMode.MONITOR,
    )
    decision = guard.inspect(
        key="mem", value="card 4111 1111 1111 1111", operation="write"
    )
    assert decision.action == Action.ALLOW
    assert "[MONITOR]" in decision.reason


# ---------------------------------------------------------------------------
# Execution strategy
# ---------------------------------------------------------------------------


def test_fail_fast_stops_after_first_match():
    from qarai_agent_guard.core.detectors.SecretsDetector import SecretsDetector

    call_log: list[str] = []

    class LoggingPIIDetector(PIIDetector):
        name = "logging_pii"

        def inspect(self, key, value, operation):
            call_log.append("pii")
            return super().inspect(key=key, value=value, operation=operation)

    class LoggingSecretsDetector(SecretsDetector):
        name = "logging_secrets"

        def inspect(self, key, value, operation):
            call_log.append("secrets")
            return super().inspect(key=key, value=value, operation=operation)

    guard = AgentGuard(
        detectors=[LoggingPIIDetector(), LoggingSecretsDetector()],
        execution_strategy=ExecutionStrategy.FAIL_FAST,
    )
    guard.inspect_with_results(
        key="mem", value="card 4111 1111 1111 1111", operation="write"
    )
    assert call_log == ["pii"]  # second detector never ran


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


def test_security_event_callbacks():
    received: list = []
    guard = AgentGuard(detectors=[PIIDetector()], event_callbacks=[received.append])

    post_received: list = []
    guard.register_callback(post_received.append)

    guard.inspect(
        key="memory",
        value="iban FR1420041010050500013M02606",
        operation="write",
        emit_events=True,
    )
    assert len(received) == 1
    assert len(post_received) == 1
    assert received[0].detector == "pii"


def test_callback_failure_logged_as_event(capsys):
    def bad_callback(event):
        raise RuntimeError("callback exploded")

    guard = AgentGuard(detectors=[PIIDetector()], event_callbacks=[bad_callback])
    guard.inspect(
        key="mem",
        value="iban FR1420041010050500013M02606",
        operation="write",
        emit_events=True,
    )
    # Failure should be printed to stderr
    captured = capsys.readouterr()
    assert "callback exploded" in captured.err
    # And logged as a CALLBACK_FAILURE event
    cb_events = [e for e in guard.events if e.event_type == EventType.CALLBACK_FAILURE]
    assert len(cb_events) == 1
    assert cb_events[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Policy loading failures
# ---------------------------------------------------------------------------


def test_policy_loading_failure_via_create(tmp_path):
    from qarai_agent_guard.core.loaders.policy_loader import PolicyLoaderError

    policy_file = tmp_path / "broken.yaml"
    policy_file.write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(PolicyLoaderError):
        AgentGuard.create(detectors=[PIIDetector()], policy_path=policy_file)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_multi_detector_redaction_fail_open():
    guard = AgentGuard(
        detectors=[PIIDetector(), _bad_redact_detector()],
        fail_behavior=FailBehavior.FAIL_OPEN,
    )
    res = guard.apply_redactions("iban FR1420041010050500013M02606")
    assert "[REDACTED:iban]" in res
    sys_events = [e for e in guard.events if e.event_type == EventType.SYSTEM_FAILURE]
    assert len(sys_events) == 1


def test_multi_detector_redaction_fail_closed():
    guard = AgentGuard(
        detectors=[PIIDetector(), _bad_redact_detector()],
        fail_behavior=FailBehavior.FAIL_CLOSED,
    )
    with pytest.raises(RedactionError, match="redact boom"):
        guard.apply_redactions("iban FR1420041010050500013M02606")


def test_selective_redaction_by_severity():
    """Only detectors matching the severity threshold should redact."""
    from qarai_agent_guard.core.schemas.detection import DetectionResult, Match

    guard = AgentGuard(detectors=[PIIDetector()])

    # Manufacture a detection with MEDIUM severity (IBAN = medium)
    detections = [
        DetectionResult(
            detector="pii",
            matched=True,
            matches=[Match("iban", "IBAN", "medium", "FR14...")],
        )
    ]

    # Threshold = HIGH → PII (medium) should be skipped
    redacted_no_op = guard.apply_redactions(
        "iban FR1420041010050500013M02606",
        severity_threshold=Severity.HIGH,
        detections=detections,
    )
    assert "[REDACTED:iban]" not in redacted_no_op

    # Threshold = MEDIUM → PII (medium) should run
    redacted = guard.apply_redactions(
        "iban FR1420041010050500013M02606",
        severity_threshold=Severity.MEDIUM,
        detections=detections,
    )
    assert "[REDACTED:iban]" in redacted


# ---------------------------------------------------------------------------
# Event metadata
# ---------------------------------------------------------------------------


def test_request_metadata_attached_to_events():
    guard = AgentGuard(detectors=[PIIDetector()])
    guard.inspect(
        key="mem",
        value="iban FR1420041010050500013M02606",
        operation="write",
        emit_events=True,
        request_metadata={"session_id": "abc-123"},
    )
    assert any(e.metadata.get("session_id") == "abc-123" for e in guard.events)


def test_event_type_classification():
    guard = AgentGuard(detectors=[PIIDetector()])
    guard.inspect(
        key="mem",
        value="iban FR1420041010050500013M02606",
        operation="write",
        emit_events=True,
    )
    detection_events = [e for e in guard.events if e.event_type == EventType.DETECTION]
    assert len(detection_events) == 1
