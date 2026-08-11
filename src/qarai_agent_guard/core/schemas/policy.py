from dataclasses import dataclass

from qarai_agent_guard.core.schemas.events import Action, Severity


@dataclass(slots=True)
class PolicyDecision:
    action: Action
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SeverityRule:
    severities: tuple[Severity, ...]
    action: Action
