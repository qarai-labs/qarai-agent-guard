from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from qarai_agent_guard.core.policies.base import (
    SeverityPolicy,
    severity_rule_from_mapping,
)
from qarai_agent_guard.core.schemas.events import Action

VALID_ACTIONS = frozenset(action.value for action in Action)
VALID_SEVERITIES = frozenset(
    {"info", "low", "medium", "high", "critical"},
)


class PolicyLoaderError(ValueError):
    """Raised when a policy file is invalid or cannot be parsed."""


class PolicyLoader:
    """Load and validate YAML policy definitions into SeverityPolicy objects.

    Supports optional root-relative paths and built-in default policy loading.
    """

    def __init__(
        self,
        root: str | Path | None = None,
    ) -> None:
        """Initialize the loader with an optional root directory.

        Args:
            root (str | Path | None, optional): Base directory for relative
                policy paths. Defaults to ``None`` (use paths as given).
        """
        if root is not None and not isinstance(root, (str, Path)):
            msg = f"root must be str, Path, or None, got {type(root).__name__}"
            raise TypeError(msg)
        self.root = Path(root) if root is not None else None

    def validate(self, data: dict[str, Any]) -> None:
        """Validate a parsed policy mapping.

        Args:
            data (dict[str, Any]): Parsed YAML policy document. Required.

        Raises:
            PolicyLoaderError: If required fields are missing or invalid.
        """
        if not isinstance(data, dict):
            msg = "Policy file must contain a mapping at the top level"
            raise PolicyLoaderError(msg)

        name = data.get("name")
        if not name:
            msg = "Policy file must define a 'name'"
            raise PolicyLoaderError(msg)

        rules = data.get("rules")
        if not isinstance(rules, list) or not rules:
            msg = "Policy file must define a non-empty 'rules' list"
            raise PolicyLoaderError(msg)

        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                msg = f"Rule at index {index} must be a mapping"
                raise PolicyLoaderError(msg)

            severities = rule.get("severities")
            if not isinstance(severities, list) or not severities:
                msg = f"Rule at index {index} must define severities"
                raise PolicyLoaderError(msg)

            for severity in severities:
                if str(severity).lower() not in VALID_SEVERITIES:
                    msg = f"Rule at index {index} has invalid severity: {severity!r}"
                    raise PolicyLoaderError(msg)

            action = rule.get("action")
            if str(action).lower() not in VALID_ACTIONS:
                msg = f"Rule at index {index} has invalid action: {action!r}"
                raise PolicyLoaderError(msg)

        default_action = data.get("default_action", "allow")
        if str(default_action).lower() not in VALID_ACTIONS:
            msg = f"Invalid default_action: {default_action!r}"
            raise PolicyLoaderError(msg)

    def load_file(
        self,
        path: str | Path,
    ) -> dict[str, Any]:
        """Load and validate a policy YAML file.

        Args:
            path (str | Path): Policy file path. Required.

        Returns:
            dict[str, Any]: Parsed and validated policy mapping.

        Raises:
            TypeError: If ``path`` is not a path-like value.
            PolicyLoaderError: If the file content is invalid.
            OSError: If the file cannot be read.
        """
        if not isinstance(path, (str, Path)):
            msg = f"path must be str or Path, got {type(path).__name__}"
            raise TypeError(msg)

        resolved = Path(path)
        if self.root is not None and not resolved.is_absolute():
            resolved = self.root / resolved

        with open(resolved, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)

        if not isinstance(data, dict):
            msg = f"Policy file must contain a mapping: {resolved}"
            raise PolicyLoaderError(msg)

        self.validate(data)
        return data

    def load(
        self,
        path: str | Path,
    ) -> SeverityPolicy:
        """Load a policy YAML file into a SeverityPolicy instance.

        Args:
            path (str | Path): Policy file path. Required.

        Returns:
            SeverityPolicy: Parsed policy object.

        Raises:
            TypeError: If ``path`` is not a path-like value.
            PolicyLoaderError: If the file content is invalid.
        """
        data = self.load_file(path)
        rules = [severity_rule_from_mapping(rule) for rule in data["rules"]]
        default_action = Action(str(data.get("default_action", "allow")).lower())
        return SeverityPolicy(
            name=str(data["name"]),
            rules=rules,
            default_action=default_action,
        )

    def load_default(self) -> SeverityPolicy:
        """Load the built-in default policy from the package.

        Returns:
            SeverityPolicy: Default packaged policy.
        """
        default_path = (
            Path(__file__).resolve().parent.parent / "policies" / "default_policy.yaml"
        )
        return self.load(default_path)
