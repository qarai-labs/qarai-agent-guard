from __future__ import annotations

import pytest

from qarai_agent_guard.core.detectors.detector import Detector
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.events import Action

from .conftest import CARD_PAYLOAD, MULTI_THREAT_PAYLOAD, SECRET_PAYLOAD


def test_register_detector_at_runtime(pii_detector):
    guard = AgentGuard(detectors=[])
    guard.register_detector(pii_detector)
    assert any(d.name == pii_detector.name for d in guard.detectors)


def test_unregister_detector(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.unregister_detector(pii_detector.name)
    assert not any(d.name == pii_detector.name for d in guard.detectors)


def test_unregister_unknown_detector_raises():
    guard = AgentGuard(detectors=[])
    with pytest.raises(ValueError, match="No detector named"):
        guard.unregister_detector("ghost")


def test_disable_and_enable_detector(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])

    guard.disable_detector(pii_detector.name)
    assert pii_detector.name in guard._disabled
    result = guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write")
    assert result.action == Action.ALLOW

    guard.enable_detector(pii_detector.name)
    assert pii_detector.name not in guard._disabled
    result = guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write")
    assert result.action == Action.BLOCK


@pytest.mark.parametrize("method_name", ["disable_detector", "enable_detector"])
def test_toggle_unknown_detector_raises(method_name: str):
    guard = AgentGuard(detectors=[])
    method = getattr(guard, method_name)
    with pytest.raises(ValueError, match="No detector named"):
        method("ghost")


def test_register_detector_rejects_non_detector():
    guard = AgentGuard(detectors=[])
    with pytest.raises(TypeError, match="detector must be Detector"):
        guard.register_detector("not-a-detector")


def test_register_duplicate_detector_raises(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    with pytest.raises(ValueError, match="is already registered"):
        guard.register_detector(Detector(name="pii", default_rules="pii"))


def test_unregister_clears_disabled_state(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    guard.disable_detector(pii_detector.name)
    guard.unregister_detector(pii_detector.name)
    assert pii_detector.name not in guard._disabled

    guard.register_detector(pii_detector)
    result = guard.inspect(key="mem", value=CARD_PAYLOAD, operation="write")
    assert result.action == Action.BLOCK


def test_disable_skips_only_that_detector(pii_detector, secrets_detector):
    guard = AgentGuard(detectors=[pii_detector, secrets_detector])
    guard.disable_detector(secrets_detector.name)
    decision, detections = guard.inspect_with_results(
        key="mem", value=SECRET_PAYLOAD, operation="write"
    )
    assert decision.action == Action.ALLOW
    assert detections == []


def test_multi_detector_disable_keeps_other_detectors_active(multi_detector_guard):
    guard = AgentGuard(detectors=multi_detector_guard.detectors)
    guard.disable_detector("secrets")
    _, detections = guard.inspect_with_results(
        key="mem", value=MULTI_THREAT_PAYLOAD, operation="write"
    )
    assert {d.detector for d in detections} == {"pii", "prompt_injection"}
