# Development & Contributing

## Project Structure

A typical project structure is:

```text
qarai-agent-guard/
├── qarai_agent_guard/
├── integrations/
│   ├── qarai-agent-guard-langchain/
│   └── qarai-agent-guard-crewai/
├── patterns/
├── tests/
├── docs/
├── assets/
├── README.md
├── mkdocs.yml
└── LICENSE
```

The exact structure may change as the project evolves.

## Development Environment

Create an isolated Python environment before installing development dependencies.

```bash
python -m venv .venv
```

Activate it according to your operating system.

Then install the project and its development dependencies using the project's packaging configuration.

## Running Tests

Use the project's configured test runner.

For example:

```bash
pytest
```

If the repository defines a different test command, use that command instead.

## Documentation

The documentation is built with MkDocs.

Start the local documentation server:

```bash
mkdocs serve
```

Build the static documentation:

```bash
mkdocs build
```

The generated `site/` directory should normally not be committed.

## Adding Documentation

Documentation pages are stored under:

```text
docs/
```

Add new pages there and register them in `mkdocs.yml`.

Example:

```yaml
nav:
  - New Topic: new-topic.md
```

## Code Quality

When contributing code:

- Keep modules focused.
- Prefer clear names.
- Add tests for new behavior.
- Avoid unnecessary dependencies.
- Keep security-sensitive behavior explicit.
- Document public APIs.
- Preserve backwards compatibility where possible.

## Security Issues

Do not publish sensitive credentials, API keys, or other secrets in issues, pull requests, logs, or documentation.

For security-sensitive reports, use the project's designated private security-reporting process if one is provided.

## Contributions

The current project policy does not accept external pull requests.

Feedback, bugs, and suggestions should be submitted through the project's issue-tracking process.

## Roadmap

The project roadmap includes:

- Additional framework integrations
- Guarded Buffer Memory
- Persistent memory backends such as Redis and PostgreSQL
- ML-powered detection models

Check the project repository for the current implementation status.
