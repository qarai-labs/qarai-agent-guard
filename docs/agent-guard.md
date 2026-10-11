# Agent Guard

`AgentGuard` is the central security engine of the library.
It runs detectors against a value, collects detections, evaluates the policy, and returns a decision.

This page describes the `AgentGuard` parameters and methods.

## Creating and Configuring Agent Guard

### Constructor

Create a guard with the `AgentGuard` constructor:

```python
from qarai_agent_guard import AgentGuard, Detector, default_policy

detector = Detector(name="pii", default_rules="pii")

guard = AgentGuard(
    detectors=[detector],
    policy=default_policy(),
)
```

You can pass a single detector or a list of detectors:

```python
guard = AgentGuard(detectors=detector)   # A single detector
guard = AgentGuard(detectors=[detector]) # A list of detectors
```

Raises:

- `TypeError` if `detectors` is not a `Detector` or a list of `Detector` objects.
- `TypeError` if `policy` does not implement the `Policy` interface.
- `TypeError` if `event_callbacks` contains a non-callable object.
- `ValueError` if two detectors have the same name.
- `ValueError` if `fail_behavior`, `security_mode`, or `execution_strategy` has an invalid value.

### Parameters

The `AgentGuard` constructor accepts these parameters:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `detectors` | `Detector` or `list[Detector]` | Required | The detectors to run on each inspection. |
| `policy` | `Policy` | `default_policy()` | Maps detections to actions. |
| `fail_behavior` | `FailBehavior` or `str` | `"fail_open"` | Reacts to detector and policy errors. |
| `security_mode` | `SecurityMode` or `str` | `"enforce"` | Selects enforce or monitor behavior. |
| `execution_strategy` | `ExecutionStrategy` or `str` | `"exhaustive"` | Selects how detectors run. |
| `event_callbacks` | `list[Callable]` | `None` | Runs for each emitted event. |

The library accepts strings instead of enum members:

```python
guard = AgentGuard(
    detectors=[detector],
    fail_behavior="fail_closed",
    security_mode="monitor",
    execution_strategy="fail_fast",
)
```

#### Detectors

The detectors to run on each inspection.

You can pass an empty list.
An empty list allows all traffic.

Each detector name must be unique.
Two detectors with the same name raise `ValueError`:

```python
from qarai_agent_guard import AgentGuard, Detector

try:
    guard = AgentGuard(
        detectors=[
            Detector(default_rules="pii"),
            Detector(default_rules="secrets"),
        ],
    )
except ValueError as exc:
    print(exc)
    # Duplicate detector name 'detector'. Each detector must have a unique name.
```

Give each detector a distinct name:

```python
guard = AgentGuard(
    detectors=[
        Detector(name="pii", default_rules="pii"),
        Detector(name="secrets", default_rules="secrets"),
    ],
)
```

#### Policy

The policy maps detections to actions.
The default policy blocks critical and high severity, redacts medium severity, and warns on low and info severity.

Pass a policy object to change the behavior:

```python
from qarai_agent_guard import strict_policy

guard = AgentGuard(detectors=[detector], policy=strict_policy())
```

See [Policies and Actions](policy.md) for all policy options.

#### Fail Behavior

`fail_behavior` defines the guard reaction when a detector fails, the policy fails, or redaction fails.

| Value | Behavior |
| --- | --- |
| `"fail_open"` | The guard allows the operation and emits a `SYSTEM_FAILURE` or `POLICY_FAILURE` event. |
| `"fail_closed"` | The guard blocks the operation. It returns `Action.BLOCK` for detector failures and raises `PolicyEvaluationError` for policy failures. |

See [Security Modes & Runtime Behaviour](runtime.md) for details.

#### Security Mode

`security_mode` defines how the guard applies policy decisions.

| Value | Behavior |
| --- | --- |
| `"enforce"` | The guard applies the policy action. |
| `"monitor"` | The guard converts `BLOCK` and `REDACT` actions to `ALLOW`. It keeps `WARN`. |

See [Security Modes & Runtime Behaviour](runtime.md) for examples.

#### Execution Strategy

`execution_strategy` defines how detectors run.

| Value | Behavior |
| --- | --- |
| `"exhaustive"` | The guard runs all active detectors. |
| `"fail_fast"` | The guard stops at the first match or the first failure. |

#### Event Callbacks

Functions that run for each emitted event.
The guards calls each callback with one `SecurityEvent` argument.

```python
def log_event(event):
    print(f"[SECURITY] {event.severity.value}: {event.message}")

guard = AgentGuard(
    detectors=[detector],
    event_callbacks=[log_event],
)
```

See [Events and Callbacks](events.md) for details.

### Creating a Guard from YAML (create method)

`AgentGuard.create` builds a guard and optionally loads the policy from a YAML file.

```python
from qarai_agent_guard import AgentGuard, Detector

guard = AgentGuard.create(
    detectors=[Detector(name="pii", default_rules="pii")],
    policy_path="my_policy.yaml",
)
```

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `detectors` | `Detector` or `list[Detector]` | Required | The detectors to run. |
| `policy` | `Policy` | `None` | An explicit policy object. |
| `policy_path` | `str` or `Path` | `None` | Path to a YAML policy file. |

The guard uses `policy_path` when `policy` is `None`.

Raises `TypeError` if `policy_path` is not a string or a `Path`.

## Inspection methods

### inspect

`inspect` runs the full pipeline and returns only the decision.

```python
decision = guard.inspect(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
)
```

Returns a `PolicyDecision` with two fields:

| Field | Type | Role |
| --- | --- | --- |
| `action` | `Action` | The action to apply. |
| `reason` | `str` | The reason for the action. |

### inspect_with_results

`inspect_with_results` runs the full pipeline and returns the decision and the detections.

```python
decision, detections = guard.inspect_with_results(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
)

print(decision.action)     # Action.REDACT
print(len(detections))     # 1
print(detections[0].detector)  # pii
```

Returns a tuple:

| Item | Type | Role |
| --- | --- | --- |
| `decision` | `PolicyDecision` | The policy outcome. |
| `detections` | `list[DetectionResult]` | Results where at least one rule or model matched. |

### check

`check` is a convenience wrapper.
It runs `inspect_with_results` with event emission enabled.

```python
decision, detections = guard.check(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
)
```

It matches the `(key, value, operation)` calling convention used by framework middleware.

### Common parameters

All inspection methods accept these parameters:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `key` | `str` | Required | The logical name or path of the value. |
| `value` | `Any` | Required | The data to inspect. |
| `operation` | `str` | Required | The operation on the value, for example `"write"`. |
| `source_class` | `SourceClass` or `str` | `SourceClass.UNKNOWN` | The provenance of the value. |
| `emit_events` | `bool` | `False` | Emits detection events when `True`. |
| `request_metadata` | `dict` | `None` | Extra context attached to emitted events. |

Raises:

- `TypeError` if `key` or `operation` is not a string.
- `ValueError` if `key` or `operation` is empty.
- `TypeError` if `source_class` is not a `SourceClass` member or one of its string values.
- `PolicyEvaluationError` if the policy fails and `fail_behavior` is `"fail_closed"`.

### source_class

`source_class` records the provenance of the value.
You can pass a `SourceClass` member or one of its string values.
The library provides these values:

| Value | Meaning |
| --- | --- |
| `"external_tool"` | The value came from an external tool. |
| `"user_input"` | The value came from the user. |
| `"agent_authored"` | The agent generated the value. |
| `"system"` | A system component generated the value. |
| `"unknown"` | The provenance is unknown. |

Attach request context to events:

```python
from qarai_agent_guard.core.schemas import SourceClass

decision = guard.inspect(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
    source_class=SourceClass.USER_INPUT,  # or source_class="user_input"
    emit_events=True,
    request_metadata={"session_id": "sess-amine-0142"},
)
```

## Redaction

### apply_redactions

`apply_redactions` removes sensitive data from a value with the active detectors.

```python
redacted = guard.apply_redactions(
    "Contact jhon.smith@yahoo.com to schedule the demo."
)

print(redacted)
# Contact [REDACTED:email] to schedule the demo.
```

Parameters:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `value` | `Any` | Required | The data to redact. |
| `severity_threshold` | `Severity` or `str` | `None` | Applies redactions from detectors whose highest match meets or exceeds this severity. `None` applies all detectors. |
| `detections` | `list[DetectionResult]` | `None` | Detection results from a previous inspection. The guard uses them to select the detectors and pass model entities. |

Example with detections from a previous inspection:

```python
text = "Contact jhon.smith@yahoo.com to schedule the demo."

_, detections = guard.inspect_with_results(
    key="profile",
    value=text,
    operation="write",
)

redacted = guard.apply_redactions(text, detections=detections)
print(redacted)
# Contact [REDACTED:email] to schedule the demo.
```

Raises `RedactionError` if a detector redaction fails and `fail_behavior` is `"fail_closed"`.

## Detector management

The guard manages detectors at runtime.

### register_detector

Add a detector at runtime.

```python
from qarai_agent_guard import Detector

secrets_detector = Detector(name="secrets", default_rules="secrets")
guard.register_detector(secrets_detector)
```

Raises `TypeError` if the argument is not a `Detector`.
Raises `ValueError` if a detector with the same name is registered.

### unregister_detector

Remove a detector by name.

```python
guard.unregister_detector("secrets")
```

Raises `ValueError` if no detector with the given name exists.

### disable_detector

Disable a registered detector without removing it.

```python
guard.disable_detector("pii")
```

The guard skips disabled detectors during inspection.
Raises `ValueError` if no detector with the given name exists.

### enable_detector

Re-enable a disabled detector.

```python
guard.enable_detector("pii")
```

Raises `ValueError` if no detector with the given name exists.

### register_callback

Register an event callback at runtime.

```python
guard.register_callback(log_event)
```

Raises `TypeError` if the argument is not callable.

## How inspection works

The guard follows this process on each inspection:

1. Validate `key`, `operation`, and `source_class`.
2. Run the active detectors through `run_detectors`.
3. Collect detection errors.
4. Evaluate the policy with the detections.
5. Apply the security mode.
6. Emit events when `emit_events` is `True`.

### run_detectors

`run_detectors` runs all active detectors and returns matched results.

```python
detections = guard.run_detectors(key="memory", value=payload, operation="write")
```

It collects caught detector exceptions into the optional `errors` list.
With `execution_strategy="fail_fast"`, it stops at the first match or the first failure.

When a detector fails, the guard wraps the exception in `DetectorExecutionError`.
The error message follows this format:

```text
Detector 'pii' failed: <original error>
```

## Events

The guard stores every emitted event in `guard.events`.

```python
guard.inspect(key="mem", value=payload, operation="write", emit_events=True)
print(len(guard.events))  # 1 for one matched detector
```

If the value matches nothing, no detection event is emitted:

```python
guard.inspect(key="mem", value="What is machine learning?", operation="write", emit_events=True)
print(len(guard.events))  # 0
```

The guard emits one detection event per matched detector.

See [Events and Callbacks](events.md) for the full event reference.
