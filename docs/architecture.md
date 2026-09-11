# Architecture & Core Concepts

## Overview

Qarai Agent Guard is organized around a central guard engine, security detectors, configurable policies, and optional framework integrations.

```text
Application / AI Agent
        |
        v
   AgentGuard
        |
        +-------------------+
        |                   |
        v                   v
    Detectors           Policies
        |                   |
        v                   v
 Security Findings     Actions
        |
        v
 Monitoring / Events
```

## Core Flow

A typical inspection follows this process:

1. An application sends a value to `AgentGuard`.
2. The guard passes the value to the enabled detectors.
3. Detectors analyze the value.
4. Findings are produced when a security rule matches.
5. The active policy determines what should happen.
6. The event can optionally be reported to monitoring callbacks.
7. The application continues, blocks the operation, raises an error, or applies a redaction depending on configuration.

## Main Concepts

### AgentGuard

`AgentGuard` is the main entry point used by applications.

It manages:

- Detector registration
- Detector activation
- Security inspections
- Redactions
- Policies
- Monitoring callbacks
- Runtime behavior

### Detectors

A detector is responsible for identifying a specific class of threat.

Built-in detectors include:

- `ModelReasoningDetector`
- `PIIDetector`
- `SecretsDetector`
- XML/security pattern detection through configured patterns

### Policies

Policies define how detected findings are handled.

A policy can map a finding's severity to an action such as:

- Allow
- Warn
- Block
- Redact
- Raise an error

### Patterns

Patterns are reusable security rules. They can be defined in YAML or supplied directly in Python.

### Runtime Modes

The guard can operate in different runtime modes, including normal enforcement and monitoring-oriented behavior.

## Design Principle

The core engine is intentionally separated from framework integrations. This keeps the security layer reusable across different AI applications and agent frameworks.
