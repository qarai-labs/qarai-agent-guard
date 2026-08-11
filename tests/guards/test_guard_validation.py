from __future__ import annotations

import pytest

from qarai_agent_guard.core.detectors.detector import Detector
from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.schemas.guard import (
    ExecutionStrategy,
    FailBehavior,
    SecurityMode,
)


def test_detectors_must_be_a_list():
    with pytest.raises(TypeError, match="detectors must be list"):
        AgentGuard(detectors=Detector(default_rules="pii"))


def test_detectors_must_be_detector_instances():
    with pytest.raises(TypeError, match="must be Detector"):
        AgentGuard(detectors=["not-a-detector"])


def test_invalid_policy_configuration():
    class NotAPolicy:
        """Missing the required `evaluate` method."""

    with pytest.raises(TypeError, match="policy must implement the Policy interface"):
        AgentGuard(detectors=[], policy=NotAPolicy())


@pytest.mark.parametrize(
    "kwarg",
    ["fail_behavior", "security_mode", "execution_strategy"],
)
def test_invalid_enum_kwarg_raises(kwarg: str):
    with pytest.raises(ValueError, match=kwarg):
        AgentGuard(detectors=[], **{kwarg: "not-a-real-value"})


def test_duplicate_detector_names_raise(pii_detector):
    duplicate = Detector(name="pii", default_rules="pii")
    with pytest.raises(ValueError, match="Duplicate detector name"):
        AgentGuard(detectors=[pii_detector, duplicate])


def test_duplicate_default_detector_name_collision():
    """Two plain Detector() instances share the class-level name by default."""
    with pytest.raises(ValueError, match="Duplicate detector name"):
        AgentGuard(
            detectors=[
                Detector(default_rules="pii"),
                Detector(default_rules="secrets"),
            ]
        )


def test_event_callbacks_must_be_a_list(pii_detector):
    with pytest.raises(TypeError, match="event_callbacks must be list"):
        AgentGuard(detectors=[pii_detector], event_callbacks=lambda e: None)


def test_event_callbacks_must_be_callable(pii_detector):
    with pytest.raises(TypeError, match="event_callbacks\\[0\\] must be callable"):
        AgentGuard(detectors=[pii_detector], event_callbacks=["not-callable"])


@pytest.mark.parametrize(
    "kwarg,enum_cls,enum_member",
    [
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_OPEN),
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_CLOSED),
        ("security_mode", SecurityMode, SecurityMode.ENFORCE),
        ("security_mode", SecurityMode, SecurityMode.MONITOR),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.EXHAUSTIVE),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.FAIL_FAST),
    ],
)
def test_accepts_enum_member(kwarg, enum_cls, enum_member):
    guard = AgentGuard(detectors=[], **{kwarg: enum_member})
    assert getattr(guard, kwarg) is enum_member


@pytest.mark.parametrize(
    "kwarg,enum_cls,enum_member",
    [
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_OPEN),
        ("fail_behavior", FailBehavior, FailBehavior.FAIL_CLOSED),
        ("security_mode", SecurityMode, SecurityMode.ENFORCE),
        ("security_mode", SecurityMode, SecurityMode.MONITOR),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.EXHAUSTIVE),
        ("execution_strategy", ExecutionStrategy, ExecutionStrategy.FAIL_FAST),
    ],
)
def test_accepts_string_value(kwarg, enum_cls, enum_member):
    guard = AgentGuard(detectors=[], **{kwarg: enum_member.value})
    assert getattr(guard, kwarg) is enum_member
