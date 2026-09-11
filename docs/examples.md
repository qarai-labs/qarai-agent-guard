### Detector Initialization

#### Using default built-in rules

Each detector ships with its own rule set. Just instantiate and use:

```python
from qarai_agent_guard import (
    AgentGuard,
    ModelReasoningDetector,
    PIIDetector,
    SecretsDetector,
)

# Each detector loads its built-in YAML rules automatically
guard = AgentGuard(
    detectors=[
        ModelReasoningDetector(lang="en"),   # prompt injection + XML injection rules
        PIIDetector(),                       # PII patterns (email, phone, IBAN, SSN, etc.)
        SecretsDetector(),                  # API keys, credentials, secret tokens
    ],
)

decision = guard.inspect(
    key="input",
    value="My IBAN is GB29NWBK60161331926819",
    operation="write",
)
print(decision.action)  # Action.REDACT
```

#### Using inline rules

Provide pattern definitions directly as a list of dictionaries:

```python
from qarai_agent_guard import AgentGuard, Detector

custom_patterns = [
    {
        "id": "internal_api_key",
        "name": "Internal API Key",
        "severity": "medium",
        "pattern": r"\bINTERNAL-[A-Z0-9]{32}\b",
    },
    {
        "id": "internal_endpoint",
        "name": "Internal Endpoint",
        "severity": "high",
        "pattern": r"https://internal\.example\.com/.*",
    },
]

detector = Detector(patterns=custom_patterns)

guard = AgentGuard(detectors=[detector])

decision = guard.inspect(
    key="config",
    value="Use key INTERNAL-ABC123DEF456GHI789JKL012MNO345PQR for auth",
    operation="write",
)
print(decision.action)  # Action.REDACT (default policy: medium = redact)
```

#### Using a YAML pattern file

Point a detector at one or more YAML files:

```python
from pathlib import Path
from qarai_agent_guard import AgentGuard, Detector

# detector_rules.yaml:
# version: "1.0"
# scope: custom
# rules:
#   - id: deploy_token
#     name: Deploy Token
#     severity: critical
#     pattern: '\bDEPLOY-[A-Z0-9]{40}\b'

detector = Detector(
    pattern_paths=[Path("detector_rules.yaml")],
)

guard = AgentGuard(detectors=[detector])
```

#### Using multiple detectors together

Combine built-in and custom detectors in a single guard:

```python
from pathlib import Path
from qarai_agent_guard import (
    AgentGuard,
    Detector,
    ModelReasoningDetector,
    PIIDetector,
    SecretsDetector,
)

guard = AgentGuard(
    detectors=[
        ModelReasoningDetector(lang="en"),
        PIIDetector(),
        SecretsDetector(),
        Detector(
            pattern_paths=[Path("custom_rules.yaml")],
            name="custom",
        ),
    ],
)

# All detectors run against every inspect call
decision = guard.inspect(
    key="memory",
    value="Send data to https://internal.example.com/api/leak",
    operation="write",
)
```

#### ModelReasoningDetector with different languages

```python
from qarai_agent_guard import AgentGuard, ModelReasoningDetector

# English (default)
guard_en = AgentGuard(
    detectors=[ModelReasoningDetector(lang="en")],
)

# Arabic
guard_ar = AgentGuard(
    detectors=[ModelReasoningDetector(lang="ar")],
)

# French
guard_fr = AgentGuard(
    detectors=[ModelReasoningDetector(lang="fr")],
)
```

#### PIIDetector with ignore rules

Exclude specific PII patterns after loading:

```python
from qarai_agent_guard import AgentGuard, PIIDetector

# Ignore email and phone number detection, keep everything else
detector = PIIDetector(ignore=frozenset({"email", "phone"}))

guard = AgentGuard(detectors=[detector])

decision = guard.inspect(
    key="profile",
    value="Email me at user@example.com",
    operation="write",
)
print(decision.action)  # Action.ALLOW (email rule ignored)
```

---