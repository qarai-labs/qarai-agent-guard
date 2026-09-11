## Detection Patterns

**qarai-agent-guard** uses configurable detection patterns to identify sensitive data and security threats.
Each pattern defines a unique identifier, description, severity level, and matching expression.

Example:

```yaml
version: "1.0"
scope: common

rules:
  - id: aws_access_key
    name: AWS Access Key
    severity: critical
    pattern: '\bAKIA[0-9A-Z]{16}\b'

  - id: aws_secret_key
    name: AWS Secret Key
    severity: critical
    pattern: (?i)aws_secret_access_key[\s]*[:=][\s"']*([A-Za-z0-9/+=]{40})
```

---