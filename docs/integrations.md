# Framework Integrations

Qarai Agent Guard separates the core security engine from framework-specific integrations.

## LangChain

The project provides:

**`qarai-agent-guard-langchain`**

The integration is intended to connect Qarai Agent Guard security checks with LangChain-based applications and agents.

Installation:

```bash
pip install qarai-agent-guard-langchain
```

Then follow the integration package's README for the version-specific setup and API.

## CrewAI

The project also provides:

**`qarai-agent-guard-crewai`**

The integration is intended for CrewAI-based agent applications.

Installation:

```bash
pip install qarai-agent-guard-crewai
```

Then follow the integration package's README for the version-specific setup and API.

## Integration Architecture

The intended architecture is:

```text
Your Agent Framework
        |
        v
Framework Integration
        |
        v
Qarai Agent Guard
        |
        +--> Detectors
        |
        +--> Policies
        |
        +--> Monitoring
```

The integration layer adapts framework-specific lifecycle events to the common Qarai Agent Guard security engine.

## Why Separate Integrations?

Keeping integrations separate provides several benefits:

- The core package remains lightweight.
- Framework dependencies are optional.
- Each framework can evolve independently.
- Applications only install the integrations they need.

## Integration Documentation

For detailed framework-specific configuration, consult the README included with each integration package:

```text
integrations/
├── qarai-agent-guard-langchain/
│   └── README.md
└── qarai-agent-guard-crewai/
    └── README.md
```
