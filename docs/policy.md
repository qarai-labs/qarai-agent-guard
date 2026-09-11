### Policies

Policies define how **qarai-agent-guard** responds to detected security events.
Each rule maps detection **severity levels** to an **action** that should be applied.

Example:

```yaml
version: "1.0"
name: default
default_action: allow
rules:
  - severities: [critical, high]
    action: block
  - severities: [medium]
    action: redact
  - severities: [low, info]
    action: warn
```

Supported **severities**:

* `info`
* `low`
* `medium`
* `high`
* `critical`

Supported **actions**:

* `allow`: Allow the operation without intervention
* `warn`: Allow while raising a security warning
* `redact`: Remove or mask sensitive content
* `block`: Prevent the operation from proceeding
* `quarantine`: Isolate content for further review

#### Default policy

The built-in default policy **blocks** critical/high severity matches, **redacts** medium severity matches, and **warns** on low/info severity matches.

```python
from qarai_agent_guard import AgentGuard, PIIDetector, default_policy

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=default_policy(),
)

decision = guard.inspect(
    key="data",
    value="My IBAN is GB29NWBK60161331926819",
    operation="write",
)
print(decision.action)  # Action.REDACT
```

#### Strict policy

Blocks medium severity and above, warns on low/info:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, strict_policy

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=strict_policy(),
)

decision = guard.inspect(
    key="data",
    value="My IBAN is GB29NWBK60161331926819",
    operation="write",
)
print(decision.action)  # Action.BLOCK
```

#### Permissive policy

Only blocks critical matches, warns on high/medium:

```python
from qarai_agent_guard import AgentGuard, PIIDetector, permissive_policy

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=permissive_policy(),
)

decision = guard.inspect(
    key="data",
    value="My IBAN is GB29NWBK60161331926819",
    operation="write",
)
print(decision.action)  # Action.WARN (PII IBAN is medium)
```

#### Loading a policy from a YAML file

```python
from pathlib import Path
from qarai_agent_guard import AgentGuard, PIIDetector, PolicyLoader

# my_policy.yaml:
# version: "1.0"
# name: my-custom-policy
# default_action: allow
# rules:
#   - severities: [critical, high]
#     action: block
#   - severities: [medium]
#     action: redact
#   - severities: [low, info]
#     action: warn

policy = PolicyLoader().load(Path("my_policy.yaml"))

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=policy,
)
```

#### Using AgentGuard.create with a policy file

The `create` class method loads the policy file for you:

```python
from pathlib import Path
from qarai_agent_guard import AgentGuard, PIIDetector

guard = AgentGuard.create(
    detectors=[PIIDetector()],
    policy_path=Path("my_policy.yaml"),
)
```

#### Building a policy inline

Construct a `SeverityPolicy` programmatically:

```python
from qarai_agent_guard import (
    AgentGuard,
    PIIDetector,
    Action,
    Severity,
    SeverityPolicy,
    SeverityRule
)

custom_policy = SeverityPolicy(
    name="inline-strict",
    rules=[
        SeverityRule(
            severities=(Severity.CRITICAL, Severity.HIGH),
            action=Action.BLOCK,
        ),
        SeverityRule(
            severities=(Severity.MEDIUM,),
            action=Action.REDACT,
        ),
        SeverityRule(
            severities=(Severity.LOW, Severity.INFO),
            action=Action.ALLOW,
        ),
    ],
    default_action=Action.ALLOW,
)

guard = AgentGuard(
    detectors=[PIIDetector()],
    policy=custom_policy,
)
```

---
