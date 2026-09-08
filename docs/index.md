# Qarai Agent Guard

<div align="center" style="margin-bottom: 7px;">
  <img src="assets/logo_qarai_agent_guard.png" alt="qarai agent guard logo" width="300" height="auto">
</div>


**Qarai Agent Guard** is a lightweight toolkit for building secure AI systems with built-in security middleware, protected memory, and AI safety models.

It helps detect and handle common threats such as:

- Prompt injection
- Jailbreak attempts
- PII leakage
- XML-based attacks
- Secrets exposure

The library also supports model-based reasoning detection for **English, Arabic, and French**.

## Quick Start

```python
from qarai_agent_guard import AgentGuard

guard = AgentGuard()

result = guard.inspect(
    key="user_input",
    value="Hello, how are you?",
    operation="input"
)

print(result)
```

## Main Components

- **AgentGuard** — central security engine.
- **Detectors** — identify security threats.
- **Policies** — define how findings are handled.
- **Patterns** — configure reusable detection rules.
- **Monitoring** — observe security events at runtime.
- **Integrations** — connect the guard to agent frameworks such as LangChain and CrewAI.

## Documentation

Use the navigation menu to explore:

- [Architecture & Core Concepts](architecture.md)
- [AgentGuard](agent-guard.md)
- [Detectors](detectors.md)
- [Detection Patterns](detection-patterns.md)
- [Policies & Actions](policies.md)
- [Runtime Security](runtime-security.md)
- [Error Handling](error-handling.md)
- [Framework Integrations](integrations.md)
- [Examples & Recipes](examples.md)
- [Development & Contributing](development.md)
