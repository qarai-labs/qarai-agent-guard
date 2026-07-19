from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from qarai_agent_guard.core.helpers.detection_utils import (
    highest_result_severity,
    highest_results_severity,
    parse_severity,
)
from qarai_agent_guard.core.schemas.detection import DetectionResult
from qarai_agent_guard.core.schemas.events import Action, Severity


@dataclass(slots=True)
class PolicyDecision:
    """Outcome of evaluating detections against a policy.

    Attributes:
        action (Action): Policy action to apply.
        reason (str): Human-readable explanation for the action.
    """

    action: Action
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SeverityRule:
    """Mapping from one or more severities to a policy action.

    Attributes:
        severities (tuple[Severity, ...]): Severities covered by this rule.
        action (Action): Action to take when the highest match severity is in
            this set.
    """

    severities: tuple[Severity, ...]
    action: Action


class Policy(Protocol):
    """Protocol for objects that map detection results to policy decisions."""

    def evaluate(
        self,
        results: list[DetectionResult],
    ) -> PolicyDecision:
        """Evaluate detection results and return a policy decision.

        Args:
            results (list[DetectionResult]): Matched detection results.
                Required.

        Returns:
            PolicyDecision: Action to apply to the guarded operation.
        """
        ...


class SeverityPolicy:
    """Map the highest matched pattern severity to a policy action.

    Walks ordered severity rules and falls back to a configured default when
    no rule matches the highest detected severity.
    """

    def __init__(
        self,
        *,
        name: str,
        rules: list[SeverityRule],
        default_action: Action = Action.ALLOW,
    ) -> None:
        """Initialize a severity-based policy.

        Args:
            name (str): Policy name. Required.
            rules (list[SeverityRule]): Ordered severity rules. Required;
                must not be empty.
            default_action (Action, optional): Action when no rule matches.
                Defaults to ``Action.ALLOW``.

        Raises:
            TypeError: If arguments have invalid types.
            ValueError: If ``name`` is empty or ``rules`` is empty.
        """
        if not isinstance(name, str):
            msg = f"name must be str, got {type(name).__name__}"
            raise TypeError(msg)
        if not name.strip():
            msg = "name must not be empty"
            raise ValueError(msg)
        if not isinstance(rules, list):
            msg = f"rules must be list, got {type(rules).__name__}"
            raise TypeError(msg)
        if not rules:
            msg = "rules must not be empty"
            raise ValueError(msg)
        if not isinstance(default_action, Action):
            msg = f"default_action must be Action, got {type(default_action).__name__}"
            raise TypeError(msg)

        self.name = name
        self.rules = rules
        self.default_action = default_action

    def evaluate(
        self,
        results: list[DetectionResult],
    ) -> PolicyDecision:
        """Evaluate detection results against configured severity rules.

        Args:
            results (list[DetectionResult]): Matched detection results.
                Required.

        Returns:
            PolicyDecision: Action and reason for the highest severity found.

        Raises:
            TypeError: If ``results`` is not a list.
        """
        if not isinstance(results, list):
            msg = f"results must be list, got {type(results).__name__}"
            raise TypeError(msg)
        if not results:
            return PolicyDecision(action=Action.ALLOW)

        highest = highest_results_severity(results)
        if highest is None:
            return PolicyDecision(action=Action.ALLOW)

        for rule in self.rules:
            if highest in rule.severities:
                return PolicyDecision(
                    action=rule.action,
                    reason=self._build_reason(results, highest),
                )

        return PolicyDecision(
            action=self.default_action,
            reason=self._build_reason(results, highest),
        )

    def _build_reason(
        self,
        results: list[DetectionResult],
        severity: Severity,
    ) -> str:
        """Build a human-readable reason for a policy decision.

        Args:
            results (list[DetectionResult]): Detection results. Required.
            severity (Severity): Highest matched severity. Required.

        Returns:
            str: Reason string for the policy decision.
        """
        for result in results:
            result_severity = highest_result_severity(result)
            if result_severity == severity and result.message:
                return result.message

        messages = [result.message for result in results if result.message]
        if messages:
            return messages[0]
        return f"Matched pattern severity: {severity.value}"


class DefaultPolicy(SeverityPolicy):
    """Built-in policy used when no custom policy is supplied.

    Blocks high and critical matches, redacts medium matches, and warns on
    low and info severities.
    """

    def __init__(self) -> None:
        """Initialize the default severity policy with built-in rules."""
        super().__init__(
            name="default",
            rules=[
                SeverityRule(
                    severities=(Severity.CRITICAL, Severity.HIGH),
                    action=Action.BLOCK,
                ),
                SeverityRule(
                    severities=(Severity.MEDIUM,),
                    action=Action.REDACT,
                ),
                SeverityRule(
                    severities=(Severity.LOW, Severity.INFO),
                    action=Action.WARN,
                ),
            ],
            default_action=Action.ALLOW,
        )


def severity_rule_from_mapping(
    mapping: dict[str, Any],
) -> SeverityRule:
    """Build a SeverityRule from a YAML policy rule mapping.

    Args:
        mapping (dict[str, Any]): Rule mapping with ``severities`` and
            ``action`` keys. Required.

    Returns:
        SeverityRule: Parsed severity rule.

    Raises:
        TypeError: If ``mapping`` is not a dictionary.
        ValueError: If required fields are missing or invalid.
    """
    if not isinstance(mapping, dict):
        msg = f"mapping must be dict, got {type(mapping).__name__}"
        raise TypeError(msg)

    severities = tuple(parse_severity(value) for value in mapping.get("severities", []))
    action_value = mapping.get("action")
    if not severities or action_value is None:
        msg = "Severity rule requires 'severities' and 'action'"
        raise ValueError(msg)

    try:
        action = Action(str(action_value).lower())
    except ValueError as exc:
        msg = f"Invalid policy action: {action_value!r}"
        raise ValueError(msg) from exc

    return SeverityRule(
        severities=severities,
        action=action,
    )
