# Detectors

Detectors are the components responsible for identifying security threats.

## Built-in Detectors

### ModelReasoningDetector

`ModelReasoningDetector` detects model-reasoning-related security patterns and supports:

- English
- French
- Arabic

It can be used when an application needs language-aware model reasoning detection.

```python
from qarai_agent_guard import ModelReasoningDetector

detector = ModelReasoningDetector()
```

### PIIDetector

`PIIDetector` detects potentially sensitive personally identifiable information.

```python
from qarai_agent_guard import PIIDetector

detector = PIIDetector()
```

Typical use cases include inspecting:

- User inputs
- Agent outputs
- Logs
- Tool arguments
- Data passed between agent components

### SecretsDetector

`SecretsDetector` identifies sensitive secret-like values.

```python
from qarai_agent_guard import SecretsDetector

detector = SecretsDetector()
```

It can help detect accidental exposure of credentials and other sensitive secret material.

## Detector Interface

The base `Detector` abstraction allows custom detectors to be integrated into the security engine.

```python
from qarai_agent_guard import Detector
```

A custom detector should follow the detector contract expected by the library and return findings in the format understood by `AgentGuard`.

## Custom Detectors

Custom detectors are useful for organization-specific requirements, such as:

- Internal identifiers
- Company-specific confidential terms
- Domain-specific attacks
- Application-specific policy violations

After creating a detector, register it with:

```python
guard.register_detector(my_detector)
```

## Choosing Detectors

Do not enable every possible detector without considering the application's data flow.

For example:

- User input may require prompt-injection and PII detection.
- Tool arguments may require secrets and PII detection.
- Agent output may require PII and secrets detection.
- Internal trusted data may require a different policy.
