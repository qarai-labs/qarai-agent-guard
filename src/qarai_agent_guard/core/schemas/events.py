from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels for detections and security events."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Policy actions that can be applied to a guarded operation."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class SourceClass(str, Enum):
    """Provenance class of a memory write.

    Drives self-reinforcement detection and per-class policy decisions.
    """

    EXTERNAL_TOOL = "external_tool"
    USER_INPUT = "user_input"
    AGENT_AUTHORED = "agent_authored"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    """Classification of security events."""

    DETECTION = "detection"
    SYSTEM_FAILURE = "system_failure"
    CALLBACK_FAILURE = "callback_failure"
    POLICY_FAILURE = "policy_failure"


@dataclass
class SecurityEvent:
    """Structured record of a guard decision, suitable for SIEM forwarding.

    Captures detector output, policy action, and request context in a
    serializable form.
    """

    detector: str
    severity: Severity
    action: Action
    key: str
    message: str
    operation: str = "write"
    source_class: SourceClass = SourceClass.UNKNOWN
    receipt_uri: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = EventType.DETECTION

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a plain dictionary.

        Returns:
            dict[str, Any]: JSON-serializable event payload.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "severity": self.severity.value,
            "action": self.action.value,
            "operation": self.operation,
            "key": self.key,
            "message": self.message,
            "source_class": self.source_class.value,
            "receipt_uri": self.receipt_uri,
            "metadata": self.metadata,
            "event_type": self.event_type.value,
        }


__all__ = ["Action", "SecurityEvent", "Severity", "SourceClass", "EventType"]
