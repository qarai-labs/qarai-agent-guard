# AgentGuard

`AgentGuard` is the main API for applying Qarai Agent Guard security checks.

## Basic Inspection

```python
from qarai_agent_guard import AgentGuard

guard = AgentGuard()

result = guard.inspect(
    key="prompt",
    value=user_prompt,
    operation="input"
)
```

The `key` identifies the inspected value, while `operation` describes the context in which it is being inspected.

## Inspecting Values

A common pattern is:

```python
result = guard.inspect(
    key="user_message",
    value="User-provided content",
    operation="input"
)
```

The result contains the information needed by the application to determine whether the value is safe according to the configured detectors and policy.

## Redaction

When sensitive information needs to be removed, use `apply_redactions()`.

```python
redacted = guard.apply_redactions(value)
```

Use redaction when the desired behavior is to sanitize data rather than reject the entire operation.

## Detector Management

Detectors can be managed dynamically.

### Register a detector

```python
guard.register_detector(my_detector)
```

### Disable a detector

```python
guard.disable_detector("detector_name")
```

### Enable a detector

```python
guard.enable_detector("detector_name")
```

### Unregister a detector

```python
guard.unregister_detector("detector_name")
```

Dynamic detector management is useful when different parts of an application require different security configurations.

## Event Callbacks

Applications can register callbacks to observe security events.

A callback can be used for:

- Logging
- Metrics
- Security dashboards
- Auditing
- Alerting

Keep callback logic lightweight so security inspection is not unnecessarily delayed.

## Monitor Mode

Monitor mode is useful when introducing Qarai Agent Guard into an existing application.

Instead of immediately enforcing every finding, monitoring allows teams to observe what would be detected and evaluate the impact before enabling stricter enforcement.

## Fail Behavior

The guard supports configurable failure behavior.

Two important strategies are:

- **Fail-open** — the application can continue when a guard operation itself encounters an internal failure.
- **Fail-closed** — the operation is rejected when the security layer cannot complete its check.

Choose the behavior according to the security requirements of the application.
