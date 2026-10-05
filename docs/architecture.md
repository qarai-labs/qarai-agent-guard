# Architecture

## Overview

The library is a guard for data that flows through AI systems.
It inspects data, detects threats, and applies a policy.

The guard has four parts:

- `AgentGuard`: the entry point.
- `Detector`: the detection layer.
- `Policy`: the decision layer.
- `PolicyExecutor`: the enforcement layer.

```text
Application / AI Agent
         |
         v
    AgentGuard
         |
         +---------------------+
         |                     |
         v                     v
     Detectors              Policy
         |                     |
         `-- detections -->   `-> decision
         |                     |
         v                     v
     PolicyExecutor ------> EnforcementResult
         |
         v
 Events (monitoring / callbacks)
```

## Core flow

A normal inspection follows these steps:

1. The application calls `inspect` with `key`, `value`, and `operation`.
2. The guard validates the input.
3. The guard runs the active detectors.
4. Each detector converts the value to text.
5. Each detector evaluates its rules or model.
6. The guard collects the matched results.
7. The guard asks the policy for a decision.
8. The guard applies the security mode to the decision.
9. The guard emits events when `emit_events=True`.
10. The guard returns the decision and the detections.



## The role of each component

### AgentGuard

`AgentGuard` is the entry point.
It manages:

- The detector list.
- Detector registration and activation.
- The policy.
- The runtime settings:
    - `security_mode`
    - `fail_behavior`
    - `execution_strategy`
- The event callbacks.

The guard methods:

- `inspect`: returns the decision.
- `inspect_with_results`: returns the decision and the detections.
- `check`: convenience wrapper that always emits events.
- `apply_redactions`: redacts content with all detectors.
- `run_detectors`: runs the detectors only.
- `register_detector`, `unregister_detector`, `disable_detector`,
  `enable_detector`: detector management.
- `register_callback`: event callback management.
- `create`: builds a guard and can load a YAML policy.

See [Agent Guard](agent-guard.md).

### Detector

A detector inspects one value.
It works in one of three modes:

- Regex detection.
- Model inference.
- Mixed detection.

The detector returns a `DetectionResult`.
The result says whether data matched and which rules or model fired.

The detector also provides redaction:
`redact` replaces matched values with a placeholder.

Detectors are plain rule engines by default.
They can use a model for inference.
A model runs on the HuggingFace Hub or on a remote OpenAI-compatible API.
A remote model adds a network call to each inspection.
See [Detectors](detectors.md) and [Model-Based Detection](models.md).

### Policy

A policy decides what happens after detection.
It receives the detection results and returns a `PolicyDecision`.

A `PolicyDecision` has an `action`:

- `allow`
- `warn`
- `redact`
- `block`
- `quarantine`

The decision also has a `reason` string.

Built-in policies:

- `default_policy`: the standard policy.
- `strict_policy`: stricter behavior.
- `permissive_policy`: more permissive behavior.

You can write your own policy.
Implement `evaluate` and `redact_decision`.
See [Policies](policy.md).

### PolicyExecutor

`PolicyExecutor` applies the decision to content.
It handles each action:

| Action | Behavior |
| --- | --- |
| `allow` | Passes the content through. |
| `warn` | Runs `on_warn` and passes the content through. |
| `redact` | Redacts the content with the guard. |
| `block` | Raises `AgentGuardViolation` or returns `blocked=True`. |
| `quarantine` | Runs `quarantine_handler` or raises. |

It returns an `EnforcementResult`.
See [Policies](policy.md).

## The inspection pipeline in detail

```python
from qarai_agent_guard import AgentGuard, Detector

guard = AgentGuard(detectors=[Detector(name="pii", default_rules="pii")])

decision, detections = guard.inspect_with_results(
    key="mem",
    value="Card 4111 1111 1111 1111",
    operation="write",
)

print(decision.action)
# Action.BLOCK

print(decision.reason)
# PII pattern detected in 'mem'

print(len(detections))
# 1

print(detections[0].detector)
# pii
```

## Runtime settings

Three settings control the runtime:

| Setting | Values | Role |
| --- | --- | --- |
| `security_mode` | `enforce`, `monitor` | How to apply the policy decision. |
| `fail_behavior` | `fail_open`, `fail_closed` | How to react to errors. |
| `execution_strategy` | `exhaustive`, `fail_fast` | How to run the detectors. |

See [Security Modes & Runtime Behaviour](runtime.md).

## Events

The guard records decisions as events.
A callback can receive every event.
Events have a stable serializable shape for SIEM forwarding.

See [Events and Callbacks](events.md).

## Patterns

Patterns are regex rules in YAML files.
The library ships three built-in rule sets:

- `pii`
- `secrets`
- `prompt_injection`

`prompt_injection` is language-dependent (`en`, `fr`, `ar`).
Custom pattern files follow the same format.

See [Detection Patterns](patterns.md).

## Errors

The library raises typed exceptions.
`GuardError` is the base class.
Loader errors are `ValueError` subclasses.
A model provider error becomes a `DetectorExecutionError` inside the guard.

See [Exceptions](exceptions.md).

## Design principle

The core engine is independent of any agent framework.
This keeps the security layer reusable.
Applications call the guard directly with `(key, value, operation)`.
The same convention works with adapters such as `AgentGuardMiddleware`.
