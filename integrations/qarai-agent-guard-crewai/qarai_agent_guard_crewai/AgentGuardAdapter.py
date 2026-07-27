from __future__ import annotations

from collections.abc import Callable
from typing import Any

from qarai_agent_guard import Action, AgentGuard, PolicyDecision

from qarai_agent_guard_crewai.exceptions import AgentGuardViolation
from qarai_agent_guard_crewai.schema import EnforcementResult
from qarai_agent_guard_crewai.utils import logger


class AgentGuardAdapter:
    """
    Central place where AgentGuard's PolicyDecision is turned into an
    actual effect: pass through, warn, redact, block, or quarantine.
    """

    def __init__(
        self,
        guard: AgentGuard,
        *,
        quarantine_handler: Callable[..., None] | None = None,
        on_violation: Callable[..., None] | None = None,
    ) -> None:
        self.guard = guard
        self.quarantine_handler = quarantine_handler
        self.on_violation = on_violation
        self._violations = 0

    @property
    def violations(self) -> int:
        return self._violations

    def _emit_safe(self, **kwargs: Any) -> None:
        """Never let telemetry emission crash the enforcement path."""
        try:
            self.guard._emit_event(**kwargs)
        except Exception:
            logger.exception("AgentGuard: failed to emit event")

    def _notify_violation(
        self, *, source: str, decision: PolicyDecision, content: Any
    ) -> None:
        self._violations += 1
        if self.on_violation is None:
            return
        try:
            self.on_violation(source=source, decision=decision, content=content)
        except Exception:
            logger.exception("AgentGuard: on_violation callback raised")

    def enforce(
        self,
        *,
        decision: PolicyDecision,
        content: Any,
        detections: list[Any] | None = None,
        source: str,
    ) -> EnforcementResult:
        """
        Execute a policy decision. This is the only place where actions
        are enforced for the CrewAI integration.
        """
        action = decision.action

        if action == Action.ALLOW:
            return EnforcementResult(content=content, action=action)

        if action == Action.WARN:
            self._emit_safe(
                detector="middleware",
                severity="medium",
                action=action,
                key=source,
                message=decision.reason,
                operation="middleware",
                source_class="unknown",
                metadata={"source": source, "reason": decision.reason},
            )
            return EnforcementResult(content=content, action=action)

        if action == Action.REDACT:
            if not detections:
                return EnforcementResult(content=content, action=action)
            try:
                redacted = self.guard.apply_redactions(content, detections=detections)
            except Exception:
                logger.exception(
                    "AgentGuard: redaction failed for source=%s, falling back to block",
                    source,
                )
                self._notify_violation(
                    source=source, decision=decision, content=content
                )
                raise AgentGuardViolation(
                    f"AgentGuard could not safely redact content from {source} "
                    f"and blocked it instead. Reason: {decision.reason}"
                ) from None
            return EnforcementResult(content=redacted, action=action, redacted=True)

        if action == Action.BLOCK:
            self._notify_violation(source=source, decision=decision, content=content)
            raise AgentGuardViolation(
                f"AgentGuard blocked execution.\n\nSource:\n{source}\n\n"
                f"Reason:\n{decision.reason}"
            )

        if action == Action.QUARANTINE:
            self._notify_violation(source=source, decision=decision, content=content)
            if self.quarantine_handler:
                try:
                    self.quarantine_handler(
                        source=source, content=content, decision=decision
                    )
                except Exception:
                    logger.exception("AgentGuard: quarantine_handler raised")
                    raise AgentGuardViolation(
                        f"Content quarantined by AgentGuard.\n\nSource:\n{source}\n\n"
                        f"Reason:\n{decision.reason}"
                    )
                return EnforcementResult(content=content, action=action, blocked=True)
            raise AgentGuardViolation(
                "Content quarantined by AgentGuard "
                "(no quarantine_handler configured).\n\n"
                f"Source:\n{source}\n\nReason:\n{decision.reason}"
            )

        logger.warning("AgentGuard: unrecognized policy action %r; blocking", action)
        self._notify_violation(source=source, decision=decision, content=content)
        raise AgentGuardViolation(
            f"AgentGuard encountered an unrecognized action ({action!r}) for "
            f"source={source} and blocked as a precaution."
        )
