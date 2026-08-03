from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.guards.config import (
    ExecutionStrategy,
    FailBehavior,
    SecurityMode,
)
from qarai_agent_guard.core.guards.exceptions import (
    DetectorExecutionError,
    PolicyEvaluationError,
    RedactionError,
)
from qarai_agent_guard.core.helpers.detection_utils import highest_result_severity
from qarai_agent_guard.core.loaders.policy_loader import PolicyLoader
from qarai_agent_guard.core.policies.base import Policy, PolicyDecision
from qarai_agent_guard.core.policies.defaults import default_policy
from qarai_agent_guard.core.schemas.detection import DetectionResult
from qarai_agent_guard.core.schemas.events import (
    Action,
    EventType,
    SecurityEvent,
    Severity,
    SourceClass,
)


class AgentGuard:
    """Central orchestration layer for detector execution and policy enforcement.

    Runs registered detectors against memory payloads, evaluates policy rules,
    emits structured security events, and supports dynamic detector management.
    """

    def __init__(
        self,
        *,
        detectors: list[BaseDetector],
        policy: Policy | None = None,
        fail_behavior: FailBehavior | str = FailBehavior.FAIL_OPEN,
        security_mode: SecurityMode | str = SecurityMode.ENFORCE,
        execution_strategy: ExecutionStrategy | str = ExecutionStrategy.EXHAUSTIVE,
        event_callbacks: list[Callable[[SecurityEvent], Any]] | None = None,
    ) -> None:
        """Initialize the guard with detectors and an optional policy.

        Args:
            detectors (list[BaseDetector]): Detector instances to run on each
                inspect call. Required; may be empty to allow all traffic.
            policy (Policy | None, optional): Policy used to map detections to
                actions. Defaults to the built-in default policy.
            fail_behavior (FailBehavior | str): How to handle execution errors:
                ``"fail_open"`` allows traffic on errors, ``"fail_closed"``
                blocks it. Defaults to ``FailBehavior.FAIL_OPEN``.
            security_mode (SecurityMode | str): ``"enforce"`` applies policy
                decisions, ``"monitor"`` logs without blocking. Defaults to
                ``SecurityMode.ENFORCE``.
            execution_strategy (ExecutionStrategy | str): ``"exhaustive"`` runs
                all detectors, ``"fail_fast"`` stops at the first match or
                failure. Defaults to ``ExecutionStrategy.EXHAUSTIVE``.
            event_callbacks (list[Callable[[SecurityEvent], Any]] | None):
                Callbacks invoked for each emitted security event.

        Raises:
            TypeError: If ``detectors`` is not a list, if any detector does not
                inherit from ``BaseDetector``, if ``policy`` is invalid, or if
                ``event_callbacks`` contains non-callable objects.
            ValueError: If ``fail_behavior``, ``security_mode``, or
                ``execution_strategy`` hold unrecognised values, or if duplicate
                detector names are registered.
        """
        if not isinstance(detectors, list):
            msg = f"detectors must be list, got {type(detectors).__name__}"
            raise TypeError(msg)

        for index, detector in enumerate(detectors):
            if not isinstance(detector, BaseDetector):
                msg = (
                    f"detectors[{index}] must inherit from BaseDetector, "
                    f"got {type(detector).__name__}"
                )
                raise TypeError(msg)

        # Validate uniqueness
        seen_names: set[str] = set()
        for detector in detectors:
            if detector.name in seen_names:
                msg = (
                    f"Duplicate detector name '{detector.name}'. "
                    "Each detector must have a unique name."
                )
                raise ValueError(msg)
            seen_names.add(detector.name)

        if policy is not None:
            if not hasattr(policy, "evaluate") or not callable(policy.evaluate):
                msg = (
                    "policy must implement the Policy interface "
                    "(have a callable 'evaluate' method)"
                )
                raise TypeError(msg)

        fail_behavior = self._coerce_enum(fail_behavior, FailBehavior, "fail_behavior")
        security_mode = self._coerce_enum(security_mode, SecurityMode, "security_mode")
        execution_strategy = self._coerce_enum(
            execution_strategy, ExecutionStrategy, "execution_strategy"
        )

        self.detectors: list[BaseDetector] = list(detectors)
        self.policy: Policy = policy or default_policy()
        self.fail_behavior: FailBehavior = fail_behavior
        self.security_mode: SecurityMode = security_mode
        self.execution_strategy: ExecutionStrategy = execution_strategy
        self.events: list[SecurityEvent] = []
        self._disabled: set[str] = set()
        self.event_callbacks: list[Callable[[SecurityEvent], Any]] = []

        if event_callbacks is not None:
            if not isinstance(event_callbacks, list):
                msg = (
                    f"event_callbacks must be list, "
                    f"got {type(event_callbacks).__name__}"
                )
                raise TypeError(msg)
            for index, cb in enumerate(event_callbacks):
                if not callable(cb):
                    msg = f"event_callbacks[{index}] must be callable"
                    raise TypeError(msg)
                self.event_callbacks.append(cb)

    @classmethod
    def create(
        cls,
        *,
        detectors: list[BaseDetector],
        policy: Policy | None = None,
        policy_path: str | Path | None = None,
        fail_behavior: FailBehavior | str = FailBehavior.FAIL_OPEN,
        security_mode: SecurityMode | str = SecurityMode.ENFORCE,
        execution_strategy: ExecutionStrategy | str = ExecutionStrategy.EXHAUSTIVE,
        event_callbacks: list[Callable[[SecurityEvent], Any]] | None = None,
    ) -> AgentGuard:
        """Build an AgentGuard, optionally loading policy from a YAML file.

        Args:
            detectors (list[BaseDetector]): Detector instances. Required.
            policy (Policy | None, optional): Explicit policy object.
            policy_path (str | Path | None, optional): Path to a YAML policy file.
            fail_behavior (FailBehavior | str): Error handling strategy.
            security_mode (SecurityMode | str): Enforcement vs monitor mode.
            execution_strategy (ExecutionStrategy | str): Detector run strategy.
            event_callbacks: Optional initial event callbacks.

        Returns:
            AgentGuard: Configured guard instance.
        """
        resolved_policy = policy
        if resolved_policy is None and policy_path is not None:
            if not isinstance(policy_path, (str, Path)):
                msg = (
                    f"policy_path must be str or Path, got {type(policy_path).__name__}"
                )
                raise TypeError(msg)
            resolved_policy = PolicyLoader().load(policy_path)
        return cls(
            detectors=detectors,
            policy=resolved_policy,
            fail_behavior=fail_behavior,
            security_mode=security_mode,
            execution_strategy=execution_strategy,
            event_callbacks=event_callbacks,
        )

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a new detector at runtime.

        Args:
            detector (BaseDetector): Detector to add.

        Raises:
            TypeError: If ``detector`` does not inherit from ``BaseDetector``.
            ValueError: If a detector with the same name is already registered.
        """
        if not isinstance(detector, BaseDetector):
            msg = (
                f"detector must inherit from BaseDetector, "
                f"got {type(detector).__name__}"
            )
            raise TypeError(msg)
        existing_names = {d.name for d in self.detectors}
        if detector.name in existing_names:
            msg = f"Detector '{detector.name}' is already registered."
            raise ValueError(msg)
        self.detectors.append(detector)

    def unregister_detector(self, name: str) -> None:
        """Remove a detector by name.

        Args:
            name (str): Detector name to remove.

        Raises:
            ValueError: If no detector with the given name is found.
        """
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                self._disabled.discard(name)
                return
        msg = f"No detector named '{name}' is registered."
        raise ValueError(msg)

    def disable_detector(self, name: str) -> None:
        """Disable a registered detector without removing it.

        Args:
            name (str): Detector name to disable.

        Raises:
            ValueError: If no detector with the given name is found.
        """
        if not any(d.name == name for d in self.detectors):
            msg = f"No detector named '{name}' is registered."
            raise ValueError(msg)
        self._disabled.add(name)

    def enable_detector(self, name: str) -> None:
        """Re-enable a previously disabled detector.

        Args:
            name (str): Detector name to enable.

        Raises:
            ValueError: If no detector with the given name is found.
        """
        if not any(d.name == name for d in self.detectors):
            msg = f"No detector named '{name}' is registered."
            raise ValueError(msg)
        self._disabled.discard(name)

    def register_callback(self, callback: Callable[[SecurityEvent], Any]) -> None:
        """Register an event callback for security events.

        Args:
            callback (Callable[[SecurityEvent], Any]): Callback function.

        Raises:
            TypeError: If ``callback`` is not callable.
        """
        if not callable(callback):
            msg = "callback must be callable"
            raise TypeError(msg)
        self.event_callbacks.append(callback)

    def run_detectors(
        self,
        *,
        key: str,
        value: Any,
        operation: str,
        errors: list[Exception] | None = None,
    ) -> list[DetectionResult]:
        """Execute all active detectors and collect matched results.

        Args:
            key (str): Memory key under inspection.
            value (Any): Payload to inspect.
            operation (str): CRUD operation name.
            errors (list[Exception] | None, optional): Accumulates any caught
                detector execution exceptions.

        Returns:
            list[DetectionResult]: Matched detection results only.
        """
        detections: list[DetectionResult] = []
        for detector in self.detectors:
            if detector.name in self._disabled:
                continue
            try:
                result = detector.inspect(key=key, value=value, operation=operation)
                if result.matched:
                    detections.append(result)
                    if self.execution_strategy == ExecutionStrategy.FAIL_FAST:
                        break
            except Exception as exc:
                wrapped = DetectorExecutionError(
                    f"Detector '{detector.name}' failed: {exc}"
                )
                if errors is not None:
                    errors.append(wrapped)
                if self.execution_strategy == ExecutionStrategy.FAIL_FAST:
                    break
        return detections

    def inspect(
        self,
        *,
        key: str,
        value: Any,
        operation: str,
        source_class: SourceClass = SourceClass.UNKNOWN,
        emit_events: bool = False,
        request_metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Inspect a payload and return the policy decision.

        Args:
            key (str): Memory key under inspection.
            value (Any): Payload to inspect.
            operation (str): CRUD operation name.
            source_class (SourceClass, optional): Provenance of the payload.
            emit_events (bool, optional): Whether to emit security events.
            request_metadata (dict | None, optional): Extra context to attach
                to emitted events.

        Returns:
            PolicyDecision: Final policy outcome.
        """
        decision, _ = self.inspect_with_results(
            key=key,
            value=value,
            operation=operation,
            source_class=source_class,
            emit_events=emit_events,
            request_metadata=request_metadata,
        )
        return decision

    def inspect_with_results(
        self,
        *,
        key: str,
        value: Any,
        operation: str,
        source_class: SourceClass = SourceClass.UNKNOWN,
        emit_events: bool = False,
        request_metadata: dict[str, Any] | None = None,
    ) -> tuple[PolicyDecision, list[DetectionResult]]:
        """Inspect a payload and return both the decision and detections.

        Args:
            key (str): Memory key under inspection.
            value (Any): Payload to inspect.
            operation (str): CRUD operation name.
            source_class (SourceClass, optional): Provenance of the payload.
            emit_events (bool, optional): Whether to emit detection security events.
            request_metadata (dict | None, optional): Extra context to attach
                to emitted events.

        Returns:
            tuple[PolicyDecision, list[DetectionResult]]: Policy outcome and
            matched detection results.

        Raises:
            TypeError: If ``source_class`` is not a SourceClass enum member.
            PolicyEvaluationError: If policy evaluation fails and
                ``fail_behavior`` is ``FAIL_CLOSED``.
        """
        self._validate_key(key)
        self._validate_operation(operation)
        if not isinstance(source_class, SourceClass):
            msg = f"source_class must be SourceClass, got {type(source_class).__name__}"
            raise TypeError(msg)

        base_meta: dict[str, Any] = {
            **(request_metadata or {}),
        }

        errors: list[Exception] = []
        detections = self.run_detectors(
            key=key, value=value, operation=operation, errors=errors
        )

        if errors:
            fail_closed = self.fail_behavior == FailBehavior.FAIL_CLOSED
            fail_action = Action.BLOCK if fail_closed else Action.ALLOW
            for exc in errors:
                self._emit_event(
                    detector="error",
                    severity=Severity.CRITICAL,
                    action=fail_action,
                    key=key,
                    message=str(exc),
                    operation=operation,
                    source_class=source_class,
                    metadata={**base_meta, "error": str(exc)},
                    event_type=EventType.SYSTEM_FAILURE,
                )
            if fail_closed:
                return PolicyDecision(
                    action=Action.BLOCK,
                    reason=str(errors[0]),
                ), detections

        try:
            decision = self.policy.evaluate(detections)
        except Exception as exc:
            policy_error = PolicyEvaluationError(f"Policy evaluation failed: {exc}")
            fail_closed = self.fail_behavior == FailBehavior.FAIL_CLOSED
            fail_action = Action.BLOCK if fail_closed else Action.ALLOW
            self._emit_event(
                detector="policy",
                severity=Severity.CRITICAL,
                action=fail_action,
                key=key,
                message=str(policy_error),
                operation=operation,
                source_class=source_class,
                metadata={**base_meta, "error": str(exc)},
                event_type=EventType.POLICY_FAILURE,
            )
            if fail_closed:
                raise policy_error from exc
            decision = PolicyDecision(action=Action.ALLOW, reason=str(policy_error))

        if self.security_mode == SecurityMode.MONITOR and (
            decision.action == Action.BLOCK or decision.action == Action.REDACT
        ):
            decision = PolicyDecision(
                action=Action.ALLOW,
                reason=f"[MONITOR] would have blocked or redacted: {decision.reason}",
            )

        if emit_events:
            for result in detections:
                severity = highest_result_severity(result) or Severity.INFO
                self._emit_event(
                    detector=result.detector,
                    severity=severity,
                    action=decision.action,
                    key=key,
                    message=result.message,
                    operation=operation,
                    source_class=source_class,
                    metadata={**base_meta, **result.metadata},
                    event_type=EventType.DETECTION,
                )

        return decision, detections

    def check(
        self,
        *,
        key: str,
        value: Any,
        operation: str,
    ):
        """Convenience wrapper used by framework middleware adapters.

        Runs the full inspect-and-decide pipeline with event emission
        enabled, matching the (key, value, operation) calling convention
        used by AgentGuardMiddleware.
        """
        return self.inspect_with_results(
            key=key,
            value=value,
            operation=operation,
            emit_events=True,
        )

    def apply_redactions(
        self,
        value: Any,
        *,
        severity_threshold: Severity | None = None,
        detections: list[DetectionResult] | None = None,
    ) -> Any:
        """Apply redaction transforms from all active detectors.

        Args:
            value (Any): Payload to redact.
            severity_threshold (Severity | None, optional): Only apply
                redactions from detectors whose highest match meets or exceeds
                this severity. ``None`` applies all detectors.
            detections (list[DetectionResult] | None, optional): Detection
                results from a previous ``inspect`` call used to filter which
                detectors should run their redactions.

        Returns:
            Any: Redacted payload after all applicable detector transforms.

        Raises:
            RedactionError: If a detector redaction fails and ``fail_behavior``
                is ``FAIL_CLOSED``.
        """
        allowed: set[str] | None = None
        if severity_threshold is not None and detections is not None:
            severity_order = [s for s in Severity]
            threshold_idx = severity_order.index(severity_threshold)
            allowed = set()
            for result in detections:
                sev = highest_result_severity(result)
                if sev is not None and severity_order.index(sev) >= threshold_idx:
                    allowed.add(result.detector)

        entities_by_detector: dict[str, list[dict[str, Any]]] = {}
        if detections is not None:
            for result in detections:
                if result.model_detection_result is None:
                    continue
                metadata = getattr(result.model_detection_result, "metadata", {}) or {}
                entities = metadata.get("entities")
                if isinstance(entities, list):
                    entities_by_detector[result.detector] = entities

        redacted = value
        for detector in self.detectors:
            if detector.name in self._disabled:
                continue
            if allowed is not None and detector.name not in allowed:
                continue
            if not hasattr(detector, "redact"):
                continue
            entities = entities_by_detector.get(detector.name)
            try:
                if entities is not None:
                    try:
                        redacted = detector.redact(redacted, entities=entities)
                    except TypeError as exc:
                        if "unexpected keyword argument" not in str(exc):
                            raise
                        redacted = detector.redact(redacted)
                else:
                    redacted = detector.redact(redacted)
            except Exception as exc:
                err = RedactionError(
                    f"Detector '{detector.name}' redaction failed: {exc}"
                )
                fail_closed = self.fail_behavior == FailBehavior.FAIL_CLOSED
                self._emit_event(
                    detector="error",
                    severity=Severity.CRITICAL,
                    action=Action.BLOCK if fail_closed else Action.ALLOW,
                    key="redact",
                    message=str(err),
                    operation="redact",
                    source_class=SourceClass.UNKNOWN,
                    metadata={"error": str(exc)},
                    event_type=EventType.SYSTEM_FAILURE,
                )
                if fail_closed:
                    raise err from exc
        return redacted

    def _emit_event(
        self,
        *,
        detector: str,
        severity: Severity,
        action: Action,
        key: str,
        message: str,
        operation: str,
        source_class: SourceClass,
        metadata: dict[str, Any],
        event_type: EventType = EventType.DETECTION,
    ) -> SecurityEvent:
        """Build, store, and broadcast a security event.

        Callbacks that raise are caught, reported to stderr, and logged as
        CALLBACK_FAILURE events (without re-triggering callbacks).
        """
        event = SecurityEvent(
            detector=detector,
            severity=severity,
            action=action,
            key=key,
            message=message,
            operation=operation,
            source_class=source_class,
            metadata=metadata,
            event_type=event_type,
        )
        self.events.append(event)

        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as cb_exc:
                print(
                    f"[AgentGuard] Callback {callback!r} raised: {cb_exc}",
                    file=sys.stderr,
                )
                failure_event = SecurityEvent(
                    detector="callback",
                    severity=Severity.HIGH,
                    action=Action.WARN,
                    key=key,
                    message=f"Callback failed: {cb_exc}",
                    operation=operation,
                    source_class=source_class,
                    metadata={"error": str(cb_exc)},
                    event_type=EventType.CALLBACK_FAILURE,
                )
                self.events.append(failure_event)

        return event

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str):
            msg = f"key must be str, got {type(key).__name__}"
            raise TypeError(msg)
        if not key.strip():
            msg = "key must not be empty"
            raise ValueError(msg)

    @staticmethod
    def _validate_operation(operation: str) -> None:
        if not isinstance(operation, str):
            msg = f"operation must be str, got {type(operation).__name__}"
            raise TypeError(msg)
        if not operation.strip():
            msg = "operation must not be empty"
            raise ValueError(msg)

    @staticmethod
    def _coerce_enum(value: Any, enum_cls: type, param: str) -> Any:
        """Coerce a string or enum value into an enum member.

        Args:
            value: Raw value (string or enum).
            enum_cls: Target enum class.
            param: Parameter name for error messages.

        Returns:
            Enum member.

        Raises:
            ValueError: If the value is not a valid enum member.
        """
        if isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(value)
        except ValueError:
            valid = [e.value for e in enum_cls]
            msg = f"{param} must be one of {valid}, got {value!r}"
            raise ValueError(msg)
