# Error Handling & Fail Behavior

Security software must define what happens when an inspection cannot be completed.

## Fail-Open

With fail-open behavior, the application is allowed to continue when the guard itself encounters an internal error.

This can reduce availability impact but may allow an operation to continue without a successful security check.

Use it only when the application's risk model allows this trade-off.

## Fail-Closed

With fail-closed behavior, an operation is rejected when the guard cannot complete its security check.

This provides stronger security guarantees but can affect application availability if the guard encounters unexpected failures.

## Choosing a Strategy

A simplified decision guide:

| Situation | Typical approach |
|---|---|
| High-security operation | Fail-closed |
| Security-critical data boundary | Fail-closed |
| Non-critical telemetry | Fail-open may be acceptable |
| Early adoption / testing | Monitor first |

The correct choice depends on the application's threat model.

## Security Findings vs Internal Errors

These are different situations:

### Security finding

A detector successfully analyzed the value and identified a security issue.

The configured policy determines the response.

### Internal guard error

The security system itself failed to perform the inspection.

The configured `FailBehavior` determines what the application should do.

Keeping these cases separate makes monitoring and incident analysis clearer.

## Recommended Error Handling

Applications should:

- Log guard failures appropriately.
- Avoid exposing sensitive input in error messages.
- Monitor repeated guard failures.
- Define explicit behavior for security-critical operations.
- Test both detector findings and internal guard failures.

## Example

```python
from qarai_agent_guard import FailBehavior

# Configure the guard according to the API exposed by your
# installed version.
```

Always check the installed version's API when configuring failure behavior because constructor and configuration options may evolve between releases.
