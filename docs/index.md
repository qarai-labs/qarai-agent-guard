# Qarai Agent Guard

<div align="center" style="margin-bottom: 7px;">
  <img src="assets/logo_qarai_agent_guard.png" alt="qarai agent guard logo" width="300" height="auto">
</div>

**Qarai Agent Guard** is a Python library that protects AI agents from security threats.
It inspects data before an agent reads it, stores it, or sends it to a tool.

The library detects these threats:

- Prompt injection
- Jailbreak attempts
- PII leakage
- XML-based attacks
- Secrets exposure

The library supports three detection modes:

- Regex-based detection
- Model-based detection
- Mixed detection

Model-based detection works with two model providers:

- Local or Hub models on HuggingFace
- Remote OpenAI-compatible API endpoints

The library ships detection rules for three languages:

- English
- French
- Arabic


## How it works

An application sends a value to `AgentGuard`.
The guard passes the value to its detectors.
Each detector returns a detection result when a rule or model matches.
The policy maps the result to an action.
The application receives the action and reacts to it.

The main components are:

| Component | Role |
| --- | --- |
| `AgentGuard` | Central security engine. It runs detectors and applies policy decisions. |
| `Detector` | Identifies a class of threat in a value. |
| `Policy` | Maps detection severities to actions. |
| `PolicyExecutor` | Applies a policy decision to content. |


## Quick start

Install the library:

```bash
pip install qarai-agent-guard
```

Create a guard with one detector and the default policy:

```python
from qarai_agent_guard import AgentGuard, Detector, default_policy

pii_detector = Detector(name="pii", default_rules="pii")

guard = AgentGuard(
    detectors=[pii_detector],
    policy=default_policy(),
)
```

Inspect a value that contains an IBAN:

```python
decision = guard.inspect(
    key="memory",
    value="Please store IBAN FR1420041010050500013M02606 on file for client Amine Trabelsi.",
    operation="write",
)

print(decision.action)   # Action.REDACT
print(decision.reason)   # PII pattern detected in 'memory'
```

The default policy redacts medium-severity matches.
The IBAN has medium severity, so the guard returns the `REDACT` action.

Inspect a value that contains a card number:

```python
decision = guard.inspect(
    key="card",
    value="Cardholder Yassine Gharbi paid with card 4111 1111 1111 1111.",
    operation="write",
)

print(decision.action)   # Action.BLOCK
```

The card number has critical severity.
The default policy returns the `BLOCK` action for critical severity.

Remove sensitive data from a value:

```python
redacted = guard.apply_redactions(
    "Contact jhon.smith@google.com to schedule the demo."
)

print(redacted)
# Contact [REDACTED:email] to schedule the demo.
```

## Documentation structure

Read the pages in this order:

| Page | What it covers |
| --- | --- |
| [Architecture & Core Concepts](architecture.md) | The design of the library. |
| [Agent Guard](agent-guard.md) | The `AgentGuard` engine, its parameters, and its methods. |
| [Detectors](detectors.md) | The `Detector` class, all detection modes, and rule resolution. |
| [Model-Based Detection](models.md) | `ModelConfig`, HuggingFace and API providers, tasks, and output formatters. |
| [Policies and Actions](policy.md) | Severities, actions, built-in policies, and custom policies. |
| [Detection Patterns](patterns.md) | The pattern file format and the built-in rule sets. |
| [Security Modes & Runtime Behaviour](runtime.md) | Security modes, fail behavior, and execution strategy. |
| [Events and Callbacks](events.md) | `SecurityEvent`, event types, and monitoring. |
| [Exceptions](exceptions.md) | The exception taxonomy of the library. |
| [LangChain Integration](langchain.md) | The `AgentGuardMiddleware` for LangChain agents. |
| [CrewAI Integration](crewai.md) | The `enable_guard` hooks for CrewAI crews. |
| [Examples and Recipes](examples.md) | Real examples with expected output. |

## Terminology

Use these terms with their exact meaning throughout this documentation:

| Term | Meaning |
| --- | --- |
| Value | The data sent to the guard for inspection. |
| Rule | A single regex detection pattern with a severity. |
| Pattern | The regex expression inside a rule. |
| Match | A rule that found a hit in the value. |
| Detection | A matched rule or a model detection. |
| Provider | The place where a model runs: `"huggingface"` or `"api"`. |
| Severity | The importance of a match. |
| Action | The guard response to a severity. |
| Decision | The policy outcome for a set of detections. |
| Event | A structured record of a guard decision. |
