# Examples & Recipes

This page provides common usage patterns.

## Basic Inspection

```python
from qarai_agent_guard import AgentGuard

guard = AgentGuard()

result = guard.inspect(
    key="user_input",
    value=user_input,
    operation="input"
)

print(result)
```

## Inspecting Multiple Values

When processing structured data, inspect security-sensitive fields individually.

```python
for key, value in payload.items():
    result = guard.inspect(
        key=key,
        value=value,
        operation="input"
    )
```

Choose the inspection granularity according to the application's data flow.

## Redacting Sensitive Data

When the desired behavior is sanitization rather than rejection:

```python
redacted_value = guard.apply_redactions(value)
```

This is useful for data that must continue through the application after sensitive portions are removed.

## Custom Detector

A custom detector can be registered with the guard:

```python
guard.register_detector(my_detector)
```

This is useful for organization-specific security rules.

## Temporarily Disable a Detector

```python
guard.disable_detector("detector_name")
```

Re-enable it with:

```python
guard.enable_detector("detector_name")
```

Remove it entirely with:

```python
guard.unregister_detector("detector_name")
```

## Monitor Before Enforcing

A practical deployment strategy is:

1. Enable monitoring.
2. Collect findings.
3. Review false positives.
4. Adjust patterns and policies.
5. Enable enforcement.
6. Continue monitoring after deployment.

## Selecting a Policy

```python
from qarai_agent_guard import (
    default_policy,
    strict_policy,
    permissive_policy,
)

default = default_policy()
strict = strict_policy()
permissive = permissive_policy()
```

Use the policy that matches the application's security requirements.

## Multilingual Model Reasoning Detection

The model reasoning detector supports English, French, and Arabic.

```python
from qarai_agent_guard import ModelReasoningDetector

detector = ModelReasoningDetector()
```

Configure it according to the API of the installed package version.

## Framework Integration

For LangChain and CrewAI applications, install the corresponding integration package and follow its package-specific documentation.

## Testing Recipe

A good test suite should include:

- Safe inputs
- Prompt-injection examples
- Jailbreak-like inputs
- PII examples
- Secret-like values
- XML attack patterns
- False-positive cases
- Detector failures
- Policy behavior
- Fail-open and fail-closed behavior
