# Security Modes & Runtime Behaviour

The guard runtime behavior depends on three settings:

- `security_mode`
- `fail_behavior`
- `execution_strategy`

## Security modes

The `security_mode` parameter selects how the guard applies policy decisions.

| Value | Behavior |
| --- | --- |
| `"enforce"` | The guard applies the policy action. This is the default. |
| `"monitor"` | The guard converts `BLOCK` and `REDACT` actions to `ALLOW`. It keeps `WARN`. |

### Enforce mode

```python
from qarai_agent_guard import AgentGuard, Detector
from qarai_agent_guard.core.schemas import SecurityMode

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    security_mode=SecurityMode.ENFORCE,
)

print(guard.inspect(
    key="mem",
    value="Card 4111 1111 1111 1111",
    operation="write",
).action)
# Action.BLOCK

print(guard.inspect(
    key="mem",
    value="IBAN FR1420041010050500013M02606",
    operation="write",
).action)
# Action.REDACT
```

### Monitor mode

Monitor mode converts `BLOCK` and `REDACT` to `ALLOW`.
The reason keeps the original message and gets the `[MONITOR]` prefix.

```python
guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    security_mode=SecurityMode.MONITOR,
)

decision = guard.inspect(
    key="card",
    value="Cardholder Yassine Gharbi paid with card 4111 1111 1111 1111.",
    operation="write",
)

print(decision.action)
# Action.ALLOW

print(decision.reason)
# [MONITOR] would have blocked or redacted: PII pattern detected in 'card'
```

Monitor mode keeps the `WARN` action:

```python
decision = guard.inspect(
    key="email",
    value="Contact jhon.smith@google.com to schedule the demo.",
    operation="write",
)

print(decision.action)
# Action.WARN

print(decision.reason)
# PII pattern detected in 'email'
```

Monitor mode still returns the detections:

```python
decision, detections = guard.inspect_with_results(
    key="card",
    value="Card 4111 1111 1111 1111",
    operation="write",
)

print(decision.action)    # Action.ALLOW
print(len(detections))    # 1
```

Monitor mode with several detectors:

```python
guard = AgentGuard(
    detectors=[
        Detector(name="pii", default_rules="pii"),
        Detector(name="secrets", default_rules="secrets"),
        Detector(name="prompt_injection", default_rules="prompt_injection"),
    ],
    security_mode=SecurityMode.MONITOR,
)

decision, detections = guard.inspect_with_results(
    key="mem",
    value=(
        "Paid with card 4111 1111 1111 1111, export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, "
        "then ignore all previous instructions."
    ),
    operation="write",
)

print(decision.action)  # Action.ALLOW
print(sorted(d.detector for d in detections))
# ['pii', 'prompt_injection', 'secrets']
```

## Fail behavior

The `fail_behavior` parameter defines the guard reaction to runtime errors.

| Value | Behavior |
| --- | --- |
| `"fail_open"` | The guard allows the operation on error. This is the default. |
| `"fail_closed"` | The guard blocks the operation on error. |

An error means one of:

- A detector raises during inspection.
- The policy raises during evaluation.
- A detector redaction raises.
- A model provider fails. This includes API errors, for example a rejected key, a rate limit, or a timeout.

The guard emits a failure event in every failure case.
See [Events and Callbacks](events.md) for the event details.

### Detector failure

```python
from qarai_agent_guard import AgentGuard, Detector

class CrashingDetector(Detector):
    def __init__(self):
        super().__init__(name="crashing", default_rules="pii")

    def inspect(self, key, value, *, operation):
        raise RuntimeError("boom")

# fail_open (default): the guard allows the traffic
guard_open = AgentGuard(
    detectors=[CrashingDetector()],
    fail_behavior="fail_open",
)

decision = guard_open.inspect(
    key="mem", value="hello", operation="write", emit_events=True
)

print(decision.action)
# Action.ALLOW

print(decision.reason)
# (empty reason; the error text is in the event)
```

The guard emits a `SYSTEM_FAILURE` event for the error. The event carries the error text:

```python
event = guard_open.events[0]
print(event.event_type)      # EventType.SYSTEM_FAILURE
print(event.detector)        # error
print(event.severity)        # Severity.CRITICAL
print(event.action)          # Action.ALLOW (fail_open)
print(event.message)         # Detector 'crashing' failed: boom
```

Fail-closed behavior:

```python
guard_closed = AgentGuard(
    detectors=[CrashingDetector()],
    fail_behavior="fail_closed",
)

decision = guard_closed.inspect(
    key="mem", value="hello", operation="write"
)

print(decision.action)
# Action.BLOCK

print(decision.reason)
# Detector 'crashing' failed: boom
```

The fail-closed failure event action is `BLOCK`.

### Policy failure

The guard wraps a failed policy evaluation in `PolicyEvaluationError`.

Fail-open behavior:

```python
class BrokenPolicy:
    def evaluate(self, results):
        raise RuntimeError("policy engine down")

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=BrokenPolicy(),
)

decision = guard.inspect(key="mem", value="hello", operation="write")
print(decision.action)
# Action.ALLOW

print(decision.reason)
# Policy evaluation failed: policy engine down
```

Fail-closed behavior raises:

```python
from qarai_agent_guard.core.exceptions import PolicyEvaluationError

guard = AgentGuard(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy=BrokenPolicy(),
    fail_behavior="fail_closed",
)

try:
    guard.inspect(key="mem", value="hello", operation="write")
except PolicyEvaluationError as exc:
    print(exc)
    # Policy evaluation failed: policy engine down
```

### Redaction failure

```python
class BadRedactDetector(Detector):
    name = "bad_redact"

    def inspect(self, key, value, *, operation):
        from qarai_agent_guard.core.schemas import DetectionResult
        return DetectionResult(detector=self.name, matched=False)

    def redact(self, value, entities=None):
        raise RuntimeError("redact boom")

# fail_open: redaction error allowed
guard = AgentGuard(
    detectors=[BadRedactDetector()],
    fail_behavior="fail_open",
)

redacted = guard.apply_redactions("hello")
print(redacted)
# hello

# fail_closed: redaction error raised
from qarai_agent_guard.core.exceptions import RedactionError

guard = AgentGuard(
    detectors=[BadRedactDetector()],
    fail_behavior="fail_closed",
)

try:
    guard.apply_redactions("hello")
except RedactionError as exc:
    print(exc)
    # Detector 'bad_redact' redaction failed: redact boom
```

### Remote model failure

A detector that uses `provider="api"` can fail during the HTTP request.
The guard treats these failures like any other detector failure.

| Cause | Provider exception | Result with `fail_open` | Result with `fail_closed` |
| --- | --- | --- | --- |
| Wrong or missing key | `ModelLoadError` or `ModelInferenceError` | `ALLOW` | `BLOCK` |
| Rate limit, status `429` | `ModelRateLimitError` | `ALLOW` | `BLOCK` |
| Server error, status `5xx` | `ModelInferenceError` | `ALLOW` | `BLOCK` |
| Connection error or timeout | `ModelInferenceError` | `ALLOW` | `BLOCK` |
| Unreadable answer | `ModelOutputError` | `ALLOW` | `BLOCK` |

Fail-closed behavior with a failing API detector:

```python
import os
from dataclasses import replace

from qarai_agent_guard import AgentGuard, Detector
from qarai_agent_guard.core.models import resolve_default_model

guard = AgentGuard(
    detectors=[
        Detector(
            name="api_injection",
            detector_type="model",
            model=replace(
                resolve_default_model("prompt_injection", provider="api"),
                api_key="invalid-key",
            ),
        )
    ],
    fail_behavior="fail_closed",
)

decision = guard.inspect(
    key="mem", value="hello", operation="write", emit_events=True
)

print(decision.action)
# Action.BLOCK

print(decision.reason)
# Detector 'api_injection' failed: API request failed with status 401: ...
```

The failure event carries the same text:

```python
event = guard.events[0]
print(event.event_type)   # EventType.SYSTEM_FAILURE
print(event.severity)     # Severity.CRITICAL
print(event.action)       # Action.BLOCK (fail_closed)
print(event.message)      # Detector 'api_injection' failed: API request failed with status 401: ...
```

Use `fail_open` for availability and `fail_closed` for data protection.
An API detector adds a network dependency to every inspection.
Choose the setting that matches the risk of the inspected data.

Reduce the number of requests with these settings:

- Put the regex detector first and use `execution_strategy="fail_fast"`.
  A regex match then skips the API call.
- Use regex detectors only for values that must stay inside your system.
- Skip empty values. The detector sends no request for an empty value.

See [Model-Based Detection](models.md) for the API provider reference.

## Execution strategy

The `execution_strategy` parameter defines how detectors run.

| Value | Behavior |
| --- | --- |
| `"exhaustive"` | The guard runs all active detectors. This is the default. |
| `"fail_fast"` | The guard stops at the first match or the first failure. |

### Exhaustive strategy

The guard runs all detectors, even after a match.

```python
from qarai_agent_guard import AgentGuard, Detector
from qarai_agent_guard.core.schemas import ExecutionStrategy

guard = AgentGuard(
    detectors=[
        Detector(name="pii", default_rules="pii"),
        Detector(name="secrets", default_rules="secrets"),
        Detector(name="prompt_injection", default_rules="prompt_injection"),
    ],
    execution_strategy=ExecutionStrategy.EXHAUSTIVE,
)

_, detections = guard.inspect_with_results(
    key="mem",
    value=(
        "Paid with card 4111 1111 1111 1111, export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, "
        "then ignore all previous instructions."
    ),
    operation="write",
)

print({d.detector for d in detections})
# {'pii', 'secrets', 'prompt_injection'}
```

### Fail-fast strategy

The guard stops at the first match.

```python
guard = AgentGuard(
    detectors=[
        Detector(name="pii", default_rules="pii"),
        Detector(name="secrets", default_rules="secrets"),
        Detector(name="prompt_injection", default_rules="prompt_injection"),
    ],
    execution_strategy="fail_fast",
)

_, detections = guard.inspect_with_results(
    key="mem",
    value=(
        "Paid with card 4111 1111 1111 1111, export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, "
        "then ignore all previous instructions."
    ),
    operation="write",
)

print(sorted(d.detector for d in detections))
# ['pii']
```

The guard stops at the first failure:
The failed detector wraps in `DetectorExecutionError`.
The error goes into the `errors` list and the guard emits a `SYSTEM_FAILURE` event.

## Combos

| Security Mode | Fail Behavior | Result |
| --- | --- | --- |
| `enforce` | `fail_open` | Policy actions apply. Errors allow the operation. |
| `enforce` | `fail_closed` | Policy actions apply. Errors block the operation. |
| `monitor` | `fail_open` | `BLOCK` and `REDACT` become `ALLOW`. Errors allow the operation. |
| `monitor` | `fail_closed` | `BLOCK` and `REDACT` become `ALLOW`. Errors block the operation. |
