<div align="center">

# qarai-agent-guard-crewai

**CrewAI integration for qarai-agent-guard that provides runtime security for AI agents through threat detection, policy enforcement, and content protection.**

[![PyPI version](https://img.shields.io/pypi/v/qarai-agent-guard-crewai.svg?color=blue)](https://pypi.org/project/qarai-agent-guard-crewai/)
[![Python Version](https://img.shields.io/pypi/pyversions/qarai-agent-guard-crewai.svg)](https://pypi.org/project/qarai-agent-guard-crewai/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)


[Overview](#overview) • [Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [How It works](#how-it-works) • [API Reference](#api-reference) • [Configuration](#configuration) • [Full Workflow Example](#full-workflow-example) • [Troubleshooting](#troubleshooting) • [FAQ](#faq)

</div>

---


## Overview

CrewAI agents can call LLMs and tools with minimal supervision. That flexibility is powerful, but it also means sensitive data (PII, secrets, credentials) or unsafe instructions can flow unchecked between the user, the model, and external tools.

`qarai-agent-guard-crewai` sits transparently inside that flow using CrewAI's built-in hook system, so you get consistent enforcement across your entire crew without touching agent or task definitions.

## Features

- **LLM input protection** — inspect messages before they reach the model.
- **LLM output protection** — inspect model responses before they propagate.
- **Tool input protection** — inspect tool arguments before execution.
- **Tool result protection** — inspect tool output before it returns to the agent.
- **Redaction** — automatically replace sensitive content with configurable placeholders.
- **Blocking** — halt execution when a policy returns `BLOCK`.
- **Quarantine** — route violations to a custom handler for review or auditing.
- **Selective hook registration** — enable only the hooks your app needs.
- **Fail-open / fail-closed control** — decide how unexpected integration errors are handled.
- **Violation & error callbacks** — observe enforcement and integration failures in real time.
- **Selective conversation scanning** — inspect only the latest message, or the full history.
- **Zero code changes to agents or tools** — enforcement is registered globally, once.

## Requirements

- Python 3.11+
- `crewai` (a compatible version installed in your environment)
- `qarai-agent-guard`

## Installation

```bash
pip install qarai-agent-guard qarai-agent-guard-crewai
```

> **Note:** This package integrates with, but does not install, CrewAI itself. Make sure `crewai` is already installed and pinned to a version compatible with your Agent Guard release.

## Quick Start

```python
from qarai_agent_guard_crewai import enable_guard
from qarai_agent_guard import (
    AgentGuard,
    ModelReasoningDetector,
    default_policy,
)

guard = AgentGuard(
    detectors=[ModelReasoningDetector(lang="en")],
    policy=default_policy(),
)

enable_guard(guard)
```

By default, `enable_guard()` registers all four hooks:

```text
before_llm_call
after_llm_call
before_tool_call
after_tool_call
```

Once registered, Agent Guard transparently evaluates every message and tool interaction that flows through your CrewAI crew.

## How It Works

```text
User message
     │
     ▼
before_llm_call
     │
     ▼
     LLM
     │
     ▼
after_llm_call
     │
     ▼
Agent decides to use a tool
     │
     ▼
before_tool_call
     │
     ▼
     Tool
     │
     ▼
after_tool_call
```

At each stage, Agent Guard evaluates content against your configured policies and returns one of five decisions: `ALLOW`, `WARN`, `REDACT`, `BLOCK`, or `QUARANTINE`.

## API Reference

### `enable_guard()`

The main entry point for the CrewAI integration.

```python
enable_guard(
    guard,
    hooks=None,
    fail_open=True,
    on_error=None,
    on_violation=None,
    quarantine_handler=None,
    scan_all_messages=False,
)
```

| Parameter             | Type                 | Default | Description                                                        |
| ---------------------- | -------------------- | ------- | -------------------------------------------------------------------- |
| `guard`                 | `AgentGuard`          | —       | A configured Agent Guard instance.                                   |
| `hooks`                 | `list[str] \| None`    | `None` (all hooks) | Subset of hooks to register.                              |
| `fail_open`            | `bool`                | `True`  | Whether unexpected integration errors are swallowed (`True`) or raised (`False`). |
| `on_error`             | `callable \| None`     | `None`  | Callback invoked on unexpected hook errors.                          |
| `on_violation`         | `callable \| None`     | `None`  | Callback invoked when content is blocked or quarantined.             |
| `quarantine_handler`   | `callable \| None`     | `None`  | Callback invoked to persist/handle quarantined content.              |
| `scan_all_messages`    | `bool`                | `False` | Whether to scan the full conversation or just the latest message.    |

### CrewAI Hooks

| Hook | Inspects | Flow |
|---|---|---|
| `before_llm_call` | Outgoing messages | `messages → Agent Guard → LLM` |
| `after_llm_call` | Model responses | `LLM → Agent Guard → next CrewAI step` |
| `before_tool_call` | Tool arguments | `tool input → Agent Guard → tool` |
| `after_tool_call` | Tool results | `tool result → Agent Guard → agent` |

## Configuration

### Selecting Hooks

All hooks are enabled by default. Register a subset if you only need partial coverage:

```python
enable_guard(
    guard,
    hooks=[
        "before_llm_call",
        "before_tool_call",
    ],
)
```

Available hook names:

```python
{
    "before_llm_call",
    "after_llm_call",
    "before_tool_call",
    "after_tool_call",
}
```

### Fail-Open vs. Fail-Closed

`fail_open` governs behaviour when an **unexpected technical error** occurs inside a hook, it does not affect intentional policy decisions.

**Fail-open (default)** — errors are logged and swallowed, the crew keeps running:

```python
enable_guard(guard, fail_open=True)
```

**Fail-closed** — errors raise `AgentGuardHookError`, halting execution:

```python
enable_guard(guard, fail_open=False)
```

> `BLOCK` and `QUARANTINE` decisions always raise `AgentGuardViolation`, regardless of `fail_open`.

### Error Callback

Observe unexpected hook errors without affecting enforcement:

```python
def handle_error(*, hook, error, context):
    print(f"Agent Guard error in {hook}: {error}")

enable_guard(guard, on_error=handle_error)
```

Callback receives `hook`, `error`, and `context`. Errors raised inside the callback are isolated and never bypass enforcement.

### Violation Callback

Get notified whenever content is blocked or quarantined:

```python
def handle_violation(*, source, decision, content):
    print(f"Violation detected: {source} -> {decision.action}")

enable_guard(guard, on_violation=handle_violation)
```

Callback receives `source`, `decision`, and `content`. This is informational only — it does not alter enforcement outcomes.

### Quarantine Handler

Persist or route quarantined content for review:

```python
def handle_quarantine(*, source, content, decision):
    print(f"Quarantined content from: {source}")
    # Store for investigation or auditing.

enable_guard(guard, quarantine_handler=handle_quarantine)
```

The quarantine handler runs **before** `AgentGuardViolation` is raised, so make sure it completes any critical persistence synchronously.

### Scanning Conversation History

By default, only the latest message is inspected to avoid repeatedly re-scanning a growing conversation:

```python
enable_guard(guard, scan_all_messages=False)
```

```python
messages = [
    {"role": "user", "content": "First message"},
    {"role": "assistant", "content": "First response"},
    {"role": "user", "content": "Latest message"},
]
# Only "Latest message" is inspected.
```

To re-evaluate the entire conversation on every call (higher latency, stronger coverage):

```python
enable_guard(guard, scan_all_messages=True)
```

### Redaction

When a policy returns `REDACT`, the integration rewrites the sanitized value directly back into the relevant CrewAI context:

```text
Before: "My IBAN is GB29NWBK60161331926819"
After:  "My IBAN is [REDACTED:iban]"
```

### Handling Policy Violations

`BLOCK` and `QUARANTINE` decisions raise `AgentGuardViolation`:

```python
from qarai_agent_guard_crewai.exceptions import AgentGuardViolation

try:
    # CrewAI execution
    ...
except AgentGuardViolation as exc:
    print(f"Execution blocked: {exc}")
```

Unexpected integration errors are handled separately via `fail_open` and `AgentGuardHookError` — see [Fail-Open vs. Fail-Closed](#fail-open-vs-fail-closed).

## Full Workflow Example

```python
from crewai import Agent, Crew, Task

from qarai_agent_guard import AgentGuard
from qarai_agent_guard_crewai import enable_guard
from qarai_agent_guard_crewai.exceptions import AgentGuardViolation


# 1. Configure Agent Guard
guard = AgentGuard(
    # Configure your detectors and policies here
)


# 2. Configure callbacks
def on_error(*, hook, error, context):
    print(f"[AgentGuard] Unexpected error in {hook}: {error}")


def on_violation(*, source, decision, content):
    print(f"[AgentGuard] Policy violation: {source} -> {decision.action}")


def quarantine_handler(*, source, content, decision):
    print(f"[AgentGuard] Quarantined content from {source}")
    # Persist content for investigation or auditing.
    # Do not continue processing the quarantined content.


# 3. Enable Agent Guard for CrewAI
adapter = enable_guard(
    guard,
    hooks=[
        "before_llm_call",
        "after_llm_call",
        "before_tool_call",
        "after_tool_call",
    ],
    fail_open=False,
    on_error=on_error,
    on_violation=on_violation,
    quarantine_handler=quarantine_handler,
    scan_all_messages=False,
)


# 4. Create your CrewAI agents
researcher = Agent(
    role="Researcher",
    goal="Research the requested topic",
    backstory="You are a careful research assistant.",
)

writer = Agent(
    role="Writer",
    goal="Produce a clear final answer",
    backstory="You turn research into useful responses.",
)


# 5. Define tasks
research_task = Task(
    description="Research the requested topic.",
    expected_output="A concise research summary.",
    agent=researcher,
)

writing_task = Task(
    description="Turn the research into a final response.",
    expected_output="A clear final response.",
    agent=writer,
)


# 6. Create and run the crew
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
)

try:
    result = crew.kickoff()
    print(result)
except AgentGuardViolation as exc:
    print(f"[AgentGuard] Crew execution blocked: {exc}")

```


## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Hooks don't seem to fire | `enable_guard()` called after `Crew.kickoff()`, or in the wrong process | Call `enable_guard()` once at startup, before any crew runs |
| `AgentGuardHookError` on every call | `fail_open=False` with a misconfigured `guard` | Verify your `AgentGuard` detector/policy configuration |
| Redaction not applied | Policy returns `WARN` or `ALLOW` instead of `REDACT` | Check your Agent Guard policy configuration for the relevant detector |
| High latency on long conversations | `scan_all_messages=True` | Switch to `scan_all_messages=False`, or scan history only on specific hooks |
| Quarantine handler runs but crew still stops | Expected behaviour | `QUARANTINE` always raises `AgentGuardViolation` after invoking the handler |

If you're still stuck, please [open an issue](https://github.com/qarai/qarai-agent-guard-crewai/issues) with a minimal reproduction.

## FAQ

**Does this modify my agents or tasks?**
No. Enforcement is registered globally through CrewAI's hook system, your `Agent`, `Task`, and `Crew` definitions stay untouched.

**Can I use only some of the hooks?**
Yes, pass a subset via the `hooks` parameter. See [Selecting Hooks](#selecting-hooks).

**What happens if a callback itself raises an exception?**
Callback failures (`on_error`, `on_violation`) are isolated and logged, they do not bypass Agent Guard enforcement or crash the crew.

**Is redaction reversible?**
No, redaction replaces sensitive values with a placeholder in place. If you need the original value for auditing, capture it via the `quarantine_handler` or your own logging before it reaches Agent Guard.
