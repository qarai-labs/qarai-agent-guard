# Detection Patterns

Detection patterns define reusable rules used by the security engine.

## Pattern Types

Patterns can target security threats such as:

- Prompt injection
- Jailbreak attempts
- XML-based attacks
- Secrets
- PII
- Other application-specific threats

## YAML Patterns

Patterns can be stored in YAML files so that security rules can be updated without changing application code.

A conceptual pattern file can look like:

```yaml
patterns:
  - name: example_pattern
    severity: high
    pattern: "example"
```

The exact schema should follow the pattern format supported by the installed Qarai Agent Guard version.

## Inline Patterns

Patterns can also be supplied directly from Python when configuration needs to be created dynamically.

This is useful for:

- Tests
- Application-specific rules
- Temporary rules
- Runtime configuration

## Pattern Organization

For maintainability, organize patterns by security category.

Example:

```text
patterns/
├── common/
│   ├── pii.yml
│   ├── secrets.yml
│   └── xmlinjection.yml
├── en/
├── fr/
└── ar/
```

Language-specific patterns can be separated from language-independent security rules.

## Best Practices

### Keep patterns focused

A pattern should identify one meaningful security condition rather than trying to match every possible case.

### Prefer reusable configuration

Use YAML when rules are shared across environments or applications.

### Test patterns

Every important pattern should have positive and negative test cases.

### Avoid excessive matching

Overly broad patterns can create false positives and make the security policy difficult to operate.

## Updating Patterns

When patterns change, test them against representative safe and malicious inputs before deploying them to production.
