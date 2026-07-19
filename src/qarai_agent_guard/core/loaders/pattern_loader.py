from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REQUIRED_RULE_FIELDS = (
    "id",
    "name",
    "severity",
    "pattern",
)

VALID_SEVERITIES = frozenset(
    {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    },
)


class PatternLoaderError(ValueError):
    """Raised when a pattern file is invalid or cannot be processed."""


class PatternLoader:
    """Load and validate YAML-based regex detection rules.

    The loader is responsible for resolving pattern file paths, parsing YAML
    files, and validating rule definitions before they are consumed by
    detectors.

    Pattern files are expected to contain a top-level ``rules`` list:

    Example:
        .. code-block:: yaml

            rules:
              - id: example_rule
                name: Example Rule
                severity: high
                pattern: "example"

    Attributes:
        root: Base directory used to resolve relative pattern file paths.
    """

    def __init__(
        self,
        root: str | Path,
    ) -> None:
        """Initialize a pattern loader.

        Args:
            root: Base directory used when resolving relative pattern paths.

        Raises:
            TypeError:
                If ``root`` is not a string or ``Path`` object.
            ValueError:
                If ``root`` is empty.
        """
        if not isinstance(root, (str, Path)):
            msg = f"root must be str or Path, got {type(root).__name__}"
            raise TypeError(msg)

        resolved_root = Path(root)

        if not str(resolved_root).strip():
            msg = "root must not be empty"
            raise ValueError(msg)

        self.root = resolved_root

    def load_file(
        self,
        path: str | Path,
    ) -> dict[str, Any]:
        """Load and parse a YAML pattern file.

        This method only validates that the YAML structure is a mapping.
        Rule-level validation is performed separately by ``validate_rules``.

        Args:
            path: Absolute or relative path to the YAML pattern file.

        Returns:
            Parsed YAML mapping.

        Raises:
            TypeError:
                If ``path`` is not a string or ``Path`` object.
            PatternLoaderError:
                If the file does not exist, is not a file, or the YAML
                top-level value is not a mapping.
            yaml.YAMLError:
                If the YAML content cannot be parsed.
        """
        if not isinstance(path, (str, Path)):
            msg = f"path must be str or Path, got {type(path).__name__}"
            raise TypeError(msg)

        resolved = Path(path)

        if not resolved.is_absolute():
            resolved = self.root / resolved

        if not resolved.exists():
            msg = f"Pattern file does not exist: {resolved}"
            raise PatternLoaderError(msg)

        if not resolved.is_file():
            msg = f"Pattern path is not a file: {resolved}"
            raise PatternLoaderError(msg)

        with open(resolved, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)

        if not isinstance(data, dict):
            msg = f"Pattern file must contain a mapping: {resolved}"
            raise PatternLoaderError(msg)

        return data

    def validate_rules(
        self,
        rules: list[dict[str, Any]],
        *,
        source: str,
    ) -> None:
        """Validate pattern rule definitions.

        Ensures every rule contains the required fields and that all field
        values have the expected types.

        Required fields:
            - ``id``: Rule identifier.
            - ``name``: Human-readable rule name.
            - ``severity``: Detection severity level.
            - ``pattern``: Regular expression pattern.

        Args:
            rules: Rule mappings to validate.
            source: Source file identifier used in error messages.

        Raises:
            TypeError:
                If ``rules`` or ``source`` has an invalid type.
            PatternLoaderError:
                If rules are empty, fields are missing, field values have
                invalid types, or severity is unsupported.
        """
        if not isinstance(rules, list):
            msg = f"rules must be list, got {type(rules).__name__}"
            raise TypeError(msg)

        if not isinstance(source, str):
            msg = f"source must be str, got {type(source).__name__}"
            raise TypeError(msg)

        if not rules:
            msg = f"No rules found in pattern file: {source}"
            raise PatternLoaderError(msg)

        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                msg = f"Rule at index {index} must be a mapping in {source}"
                raise PatternLoaderError(msg)

            missing = [field for field in REQUIRED_RULE_FIELDS if field not in rule]

            if missing:
                msg = (
                    f"Rule at index {index} in {source} "
                    f"is missing fields: {', '.join(missing)}"
                )
                raise PatternLoaderError(msg)

            for field in REQUIRED_RULE_FIELDS:
                if not isinstance(rule[field], str):
                    msg = (
                        f"Rule '{rule.get('id', index)}' in {source} "
                        f"field '{field}' must be a string, "
                        f"got {type(rule[field]).__name__}"
                    )
                    raise PatternLoaderError(msg)

            severity = rule["severity"].lower()

            if severity not in VALID_SEVERITIES:
                msg = (
                    f"Rule '{rule['id']}' in {source} "
                    f"has invalid severity: {rule['severity']!r}"
                )
                raise PatternLoaderError(msg)

    def load_patterns(
        self,
        path: str | Path,
    ) -> list[dict[str, Any]]:
        """Load and validate detection rules from a YAML file.

        This is the main public method used by detectors. It loads the YAML
        file, extracts the ``rules`` section, validates each rule, and
        returns ready-to-use rule definitions.

        Args:
            path: Absolute or relative path to the pattern YAML file.

        Returns:
            A list of validated rule mappings.

        Raises:
            TypeError:
                If ``path`` is not a string or ``Path`` object.
            PatternLoaderError:
                If the file content or rule definitions are invalid.
            yaml.YAMLError:
                If the YAML content cannot be parsed.
        """
        if not isinstance(path, (str, Path)):
            msg = f"path must be str or Path, got {type(path).__name__}"
            raise TypeError(msg)

        resolved = Path(path)

        if not resolved.is_absolute():
            resolved = self.root / resolved

        data = self.load_file(resolved)

        rules = data.get("rules", [])

        if not isinstance(rules, list):
            msg = f"'rules' must be a list in {resolved}"
            raise PatternLoaderError(msg)

        self.validate_rules(
            rules,
            source=str(resolved),
        )

        return rules
