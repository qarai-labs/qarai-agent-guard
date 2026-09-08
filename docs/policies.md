# Policies & Actions

Policies determine what the guard should do after a detector reports a finding.

## Policy Components

Qarai Agent Guard exposes policy-related components including:

- `default_policy()`
- `strict_policy()`
- `permissive_policy()`
- `PolicyLoader`
- `SeverityPolicy`
- `SeverityRule`
- `Action`
- `Severity`
- `SecurityMode`
- `FailBehavior`

## Default Policy

Use the default policy when the application's security requirements match the library's standard behavior.

```python
from qarai_agent_guard import default_policy

policy = default_policy()
```

## Strict Policy

A strict policy is appropriate when security enforcement should be more restrictive.

```python
from qarai_agent_guard import strict_policy

policy = strict_policy()
```

## Permissive Policy

A permissive policy is useful for applications that want to observe or warn about findings without aggressively blocking operations.

```python
from qarai_agent_guard import permissive_policy

policy = permissive_policy()
```

## Severity

Findings can have different severity levels.

The exact levels depend on the library configuration, but severity is used to distinguish the impact of different security findings.

```python
from qarai_agent_guard import Severity
```

## Actions

An `Action` represents what happens after a finding is evaluated.

Typical actions include:

- Allow
- Warn
- Block
- Redact
- Raise an error

```python
from qarai_agent_guard import Action
```

## Severity Rules

`SeverityRule` connects a severity level to a configured action.

```python
from qarai_agent_guard import SeverityRule
```

This allows policies to express rules such as:

```text
low severity    -> warn
medium severity -> redact
high severity   -> block
```

The actual policy should be selected according to the application's threat model.

## Security Modes

`SecurityMode` controls the general operating behavior of the security engine.

Use a less disruptive mode during adoption and testing, then move toward enforcement as the application's security rules become validated.

## Policy Loading

`PolicyLoader` provides a way to load policies from external configuration.

This is useful when security configuration should be maintained separately from application logic.
