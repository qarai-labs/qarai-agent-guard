from __future__ import annotations

from qarai_agent_guard.core.detectors.BaseDetector import DetectionResult, Match
from qarai_agent_guard.core.policies.base import (
    DefaultPolicy,
    SeverityPolicy,
    SeverityRule,
)
from qarai_agent_guard.core.policies.defaults import permissive_policy, strict_policy
from qarai_agent_guard.core.schemas.events import Action, Severity


def _result(severity: str, message: str = "hit") -> DetectionResult:
    return DetectionResult(
        detector="test",
        matched=True,
        message=message,
        matches=[
            Match("id", "Name", severity, "match"),
        ],
    )


def test_default_policy_blocks_high_severity():
    policy = DefaultPolicy()
    decision = policy.evaluate([_result("high")])
    assert decision.action == Action.BLOCK


def test_default_policy_redacts_medium_severity():
    policy = DefaultPolicy()
    decision = policy.evaluate([_result("medium")])
    assert decision.action == Action.REDACT


def test_default_policy_warns_on_low_severity():
    policy = DefaultPolicy()
    decision = policy.evaluate([_result("low")])
    assert decision.action == Action.WARN


def test_default_policy_allows_clean_results():
    policy = DefaultPolicy()
    decision = policy.evaluate([])
    assert decision.action == Action.ALLOW


def test_strict_policy_blocks_medium():
    policy = strict_policy()
    decision = policy.evaluate([_result("medium")])
    assert decision.action == Action.BLOCK


def test_permissive_policy_warns_on_high():
    policy = permissive_policy()
    decision = policy.evaluate([_result("high")])
    assert decision.action == Action.WARN


def test_severity_policy_uses_highest_match_across_results():
    policy = SeverityPolicy(
        name="custom",
        rules=[
            SeverityRule(
                severities=(Severity.CRITICAL,),
                action=Action.BLOCK,
            ),
        ],
    )
    results = [
        _result("low"),
        _result("critical", message="critical hit"),
    ]
    decision = policy.evaluate(results)
    assert decision.action == Action.BLOCK
    assert decision.reason == "critical hit"
