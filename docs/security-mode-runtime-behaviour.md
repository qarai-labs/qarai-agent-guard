### Security Modes

#### Monitor mode

Logs detections without blocking or redacting:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, SecurityMode

guard = AgentGuard(
    detectors=[PIIDetector()],
    security_mode=SecurityMode.MONITOR,
)

decision = guard.inspect(
    key="data",
    value="My IBAN is GB29NWBK60161331926819",
    operation="write",
)
print(decision.action)   # Action.ALLOW (monitor mode overrides block/redact)
print(decision.reason)   # "[MONITOR] would have blocked or redacted: Personally identifiable information detected in 'data'"
```

---

### Event Callbacks

Register callbacks to receive security events for logging or SIEM forwarding:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, default_policy

def log_event(event):
    print(f"[SECURITY] {event.severity.value}: {event.message}")

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=default_policy(),
    event_callbacks=[log_event],
)

guard.inspect(
    key="memory",
    value="My IBAN is FR1420041010050500013M02606",
    operation="write",
    emit_events=True,
)
# Prints: [SECURITY] medium: Personally identifiable information detected in 'memory'
```

---

### Dynamic Detector Management

Add, remove, enable, or disable detectors at runtime:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, SecretsDetector

guard = AgentGuard(detectors=[PIIDetector()])

# Register a new detector at runtime
guard.register_detector(SecretsDetector())

# Disable a detector temporarily
guard.disable_detector("pii")
decision = guard.inspect(
    key="data",
    value="My IBAN is FR1420041010050500013M02606",
    operation="write",
)
print(decision.action)  # Action.ALLOW (PII detector disabled)

# Re-enable it
guard.enable_detector("pii")

# Remove a detector entirely
guard.unregister_detector("secrets")
```

---

### Fail Behavior

Control how the guard handles detector or policy errors:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, FailBehavior

# fail_open (default): allow traffic if a detector crashes
guard_open = AgentGuard(
    detectors=[PIIDetector()],
    fail_behavior=FailBehavior.FAIL_OPEN,
)

# fail_closed: block traffic if a detector crashes
guard_closed = AgentGuard(
    detectors=[PIIDetector()],
    fail_behavior=FailBehavior.FAIL_CLOSED,
)
```

---
