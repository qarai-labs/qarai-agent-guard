from __future__ import annotations

from qarai_agent_guard.core.policies.base import (
    DefaultPolicy,
    SeverityPolicy,
    SeverityRule,
)
from qarai_agent_guard.core.schemas.events import Action, Severity


def default_policy() -> DefaultPolicy:
    """Return the built-in default severity policy.

    Returns:
        DefaultPolicy: Policy that blocks high/critical, redacts medium, and
        warns on low/info matches.
    """
    return DefaultPolicy()


def strict_policy() -> SeverityPolicy:
    """Return a strict policy that blocks medium severity and above.

    Returns:
        SeverityPolicy: Strict policy instance.
    """
    return SeverityPolicy(
        name="strict",
        rules=[
            SeverityRule(
                severities=(
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                ),
                action=Action.BLOCK,
            ),
            SeverityRule(
                severities=(Severity.LOW, Severity.INFO),
                action=Action.WARN,
            ),
        ],
        default_action=Action.ALLOW,
    )


def permissive_policy() -> SeverityPolicy:
    """Return a permissive policy that only blocks critical matches.

    Returns:
        SeverityPolicy: Permissive policy instance.
    """
    return SeverityPolicy(
        name="permissive",
        rules=[
            SeverityRule(
                severities=(Severity.CRITICAL,),
                action=Action.BLOCK,
            ),
            SeverityRule(
                severities=(Severity.HIGH, Severity.MEDIUM),
                action=Action.WARN,
            ),
        ],
        default_action=Action.ALLOW,
    )
