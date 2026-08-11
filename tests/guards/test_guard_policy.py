from __future__ import annotations

from pathlib import Path

import pytest

from qarai_agent_guard.core.guards.agent_guard import AgentGuard
from qarai_agent_guard.core.loaders.policy_loader import PolicyLoader, PolicyLoaderError
from qarai_agent_guard.core.policies.base import (
    SeverityPolicy,
    SeverityRule,
    severity_rule_from_mapping,
)
from qarai_agent_guard.core.policies.defaults import (
    default_policy,
    permissive_policy,
    strict_policy,
)
from qarai_agent_guard.core.schemas.events import Action, Severity
from qarai_agent_guard.core.schemas.policy import PolicyDecision

from .conftest import (
    CARD_PAYLOAD,
    EMAIL_PAYLOAD,
    IBAN_PAYLOAD,
    PROMPT_INJECTION_PAYLOAD,
    SAFE_PAYLOAD,
)


def test_agent_guard_create_with_policy_path(tmp_path: Path, prompt_injection_detector):
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
        detectors=[prompt_injection_detector],
        policy_path=policy_file,
    )
    decision = guard.inspect(
        key="memory", value=PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


def test_create_rejects_non_path_policy_path(prompt_injection_detector):
    with pytest.raises(TypeError, match="policy_path must be str or Path"):
        AgentGuard.create(detectors=[prompt_injection_detector], policy_path=12345)


def test_policy_loading_failure_via_create(tmp_path: Path, pii_detector):
    policy_file = tmp_path / "broken.yaml"
    policy_file.write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(PolicyLoaderError):
        AgentGuard.create(detectors=[pii_detector], policy_path=policy_file)


# Same payload evaluated under different policies


@pytest.mark.parametrize(
    "policy_factory,expected_action",
    [
        (default_policy, Action.REDACT),
        (strict_policy, Action.BLOCK),
        (permissive_policy, Action.WARN),
    ],
)
def test_same_medium_payload_different_policies(
    pii_detector,
    policy_factory,
    expected_action,
):
    """The same IBAN payload gets a different action per policy."""
    guard = AgentGuard(detectors=[pii_detector], policy=policy_factory())
    decision = guard.inspect(key="memory", value=IBAN_PAYLOAD, operation="write")
    assert decision.action == expected_action


@pytest.mark.parametrize(
    "policy_factory",
    [default_policy, strict_policy, permissive_policy],
)
def test_critical_threat_blocked_under_all_policies(
    policy_factory,
    prompt_injection_detector,
):
    """A critical-severity threat is blocked regardless of the policy."""
    guard = AgentGuard(
        detectors=[prompt_injection_detector],
        policy=policy_factory(),
    )
    decision = guard.inspect(
        key="memory", value=PROMPT_INJECTION_PAYLOAD, operation="write"
    )
    assert decision.action == Action.BLOCK


@pytest.mark.parametrize(
    "policy_factory,expected_action",
    [
        (default_policy, Action.WARN),
        (strict_policy, Action.WARN),
        (permissive_policy, Action.ALLOW),
    ],
)
def test_low_severity_behavior_differs_by_policy(
    pii_detector,
    policy_factory,
    expected_action,
):
    """Low-severity email is only allowed by the permissive policy."""
    guard = AgentGuard(detectors=[pii_detector], policy=policy_factory())
    decision = guard.inspect(key="memory", value=EMAIL_PAYLOAD, operation="write")
    assert decision.action == expected_action


# Custom policies


def test_custom_severity_policy(pii_detector):
    policy = SeverityPolicy(
        name="custom",
        rules=[
            SeverityRule(
                severities=(Severity.CRITICAL,),
                action=Action.QUARANTINE,
            ),
            SeverityRule(
                severities=(Severity.MEDIUM,),
                action=Action.WARN,
            ),
        ],
        default_action=Action.ALLOW,
    )
    guard = AgentGuard(detectors=[pii_detector], policy=policy)

    assert (
        guard.inspect(key="memory", value=CARD_PAYLOAD, operation="write").action
        == Action.QUARANTINE
    )
    assert (
        guard.inspect(key="memory", value=IBAN_PAYLOAD, operation="write").action
        == Action.WARN
    )
    assert (
        guard.inspect(key="memory", value=EMAIL_PAYLOAD, operation="write").action
        == Action.ALLOW
    )


def test_custom_policy_object_implementing_evaluate(pii_detector):
    class AlwaysWarnPolicy:
        def evaluate(self, results):
            if results:
                return PolicyDecision(action=Action.WARN, reason="something matched")
            return PolicyDecision(action=Action.ALLOW)

    guard = AgentGuard(detectors=[pii_detector], policy=AlwaysWarnPolicy())
    assert (
        guard.inspect(key="memory", value=CARD_PAYLOAD, operation="write").action
        == Action.WARN
    )
    assert (
        guard.inspect(key="memory", value=SAFE_PAYLOAD, operation="write").action
        == Action.ALLOW
    )


def test_policy_rules_are_ordered_first_match_wins(pii_detector):
    """Among rules covering the same severity, the first one in the list wins."""
    policy = SeverityPolicy(
        name="ordered",
        rules=[
            SeverityRule(severities=(Severity.CRITICAL,), action=Action.QUARANTINE),
            SeverityRule(severities=(Severity.CRITICAL,), action=Action.BLOCK),
        ],
        default_action=Action.ALLOW,
    )
    guard = AgentGuard(detectors=[pii_detector], policy=policy)
    decision = guard.inspect(key="memory", value=CARD_PAYLOAD, operation="write")
    assert decision.action == Action.QUARANTINE


def test_policy_decision_reason_uses_detector_message(pii_detector):
    guard = AgentGuard(detectors=[pii_detector])
    decision = guard.inspect(key="memory", value=CARD_PAYLOAD, operation="write")
    assert decision.action == Action.BLOCK
    assert decision.reason == "PII pattern detected in 'memory'"


def test_severity_policy_returns_allow_for_empty_results():
    decision = default_policy().evaluate([])
    assert decision.action == Action.ALLOW
    assert decision.reason == ""


def test_severity_rule_from_mapping_requires_both_fields():
    with pytest.raises(ValueError, match="requires 'severities' and 'action'"):
        severity_rule_from_mapping({"severities": ["high"]})


# Policy loading


def test_policy_loader_loads_yaml_file(tmp_path: Path):
    policy_file = tmp_path / "custom.yaml"
    policy_file.write_text(
        """
name: loaded
default_action: allow
rules:
  - severities: [critical, high]
    action: block
""".strip(),
        encoding="utf-8",
    )
    policy = PolicyLoader().load(policy_file)
    assert policy.name == "loaded"
    assert policy.default_action == Action.ALLOW
    assert policy.rules[0].action == Action.BLOCK


def test_policy_loader_load_default():
    policy = PolicyLoader().load_default()
    assert policy.name == "default"
    assert policy.rules[0].action == Action.BLOCK


@pytest.mark.parametrize(
    "content,error_match",
    [
        (
            "rules:\n  - severities: [high]\n    action: block\n",
            "'name'",
        ),
        (
            "name: x\nrules: []\n",
            "non-empty 'rules'",
        ),
        (
            "name: x\nrules:\n  - severities: [severe]\n    action: block\n",
            "invalid severity",
        ),
        (
            "name: x\nrules:\n  - severities: [high]\n    action: explode\n",
            "invalid action",
        ),
        (
            "name: x\ndefault_action: explode\n"
            "rules:\n  - severities: [high]\n    action: block\n",
            "Invalid default_action",
        ),
        (
            "- a\n- b\n",
            "mapping",
        ),
    ],
)
def test_policy_loader_rejects_invalid_files(
    tmp_path: Path,
    content: str,
    error_match: str,
):
    policy_file = tmp_path / "invalid.yaml"
    policy_file.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyLoaderError, match=error_match):
        PolicyLoader().load_file(policy_file)


def test_create_prefers_explicit_policy_over_policy_path(tmp_path: Path, pii_detector):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "name: strict-file\ndefault_action: allow\n"
        "rules:\n  - severities: [critical, high, medium, low]\n    action: block\n",
        encoding="utf-8",
    )
    permissive = permissive_policy()
    guard = AgentGuard.create(
        detectors=[pii_detector],
        policy=permissive,
        policy_path=policy_file,
    )
    assert guard.policy is permissive
    decision = guard.inspect(key="memory", value=CARD_PAYLOAD, operation="write")
    assert decision.action == Action.BLOCK
