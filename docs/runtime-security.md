# Runtime Security & Monitoring

Qarai Agent Guard can be integrated directly into an application's runtime flow.

## Where to Inspect

Security checks can be placed at important boundaries.

Typical locations include:

```text
User Input
    |
    v
 Agent / Application
    |
    +----> Tool Arguments
    |
    +----> Memory
    |
    +----> Model Input
    |
    v
 Model Output
    |
    v
 User Output
```

Inspect data at the boundaries where untrusted or sensitive information enters or leaves the system.

## Input Inspection

Inspect user-controlled input before passing it to an agent or model.

```python
guard.inspect(
    key="user_input",
    value=user_input,
    operation="input"
)
```

## Tool Inspection

Tool arguments can contain sensitive or malicious content. Inspect them before execution when appropriate.

## Output Inspection

Model and agent outputs can also require inspection, especially when they may contain:

- PII
- Secrets
- Sensitive internal information

## Monitoring

Monitoring mode is useful for collecting security findings without immediately changing application behavior.

It can help teams answer:

- Which detectors trigger most often?
- Which inputs produce false positives?
- Which parts of the application generate security findings?
- What would happen if enforcement were enabled?

## Event Callbacks

Callbacks can forward findings to an application's logging or monitoring system.

Possible destinations include:

- Application logs
- Metrics systems
- Security dashboards
- Audit pipelines

## Runtime Configuration

Detectors can be enabled or disabled dynamically:

```python
guard.disable_detector("detector_name")
guard.enable_detector("detector_name")
```

This allows different runtime environments to use different security configurations.

## Production Considerations

Before enabling strict enforcement in production:

1. Test detectors against representative traffic.
2. Review false positives.
3. Validate policy actions.
4. Decide on fail-open versus fail-closed behavior.
5. Add monitoring and alerting.
6. Roll out enforcement gradually.
