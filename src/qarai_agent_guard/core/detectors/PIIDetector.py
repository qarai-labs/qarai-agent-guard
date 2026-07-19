from __future__ import annotations

from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT


class PIIDetector(BaseDetector):
    """Detect personally identifiable information patterns.

    This detector loads common PII detection rules and scans payloads for
    sensitive information patterns. Specific rules can be excluded using
    the ``ignore`` option before regex compilation.

    Attributes:
        name: Unique detector identifier.
        default_message: Message returned when PII is detected.
    """

    name = "pii"
    default_message = "Personally identifiable information detected"

    def __init__(
        self,
        *,
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        ignore: frozenset[str] | None = None,
        loader: PatternLoader | None = None,
    ) -> None:
        """Initialize the PII detector.

        Args:
            patterns: Optional inline PII rules. When provided, these replace
                the default rules loaded from the pattern repository.
            ignore: Optional set of rule identifiers to exclude after loading
                the pattern definitions.
            loader: Optional pattern loader instance. If omitted, a loader
                using the built-in pattern directory is created.

        Raises:
            TypeError:
                If ``ignore`` is not a ``frozenset`` or ``loader`` is not a
                ``PatternLoader`` instance.
        """
        if ignore is not None and not isinstance(ignore, frozenset):
            msg = f"ignore must be frozenset or None, got {type(ignore).__name__}"
            raise TypeError(msg)

        if loader is not None and not isinstance(loader, PatternLoader):
            msg = f"loader must be PatternLoader or None, got {type(loader).__name__}"
            raise TypeError(msg)

        self._ignore = ignore or frozenset()

        super().__init__(
            lang="common",
            patterns=patterns,
            pattern_paths=pattern_paths,
            loader=loader or PatternLoader(PATTERNS_ROOT),
        )

        if self._ignore:
            self._rules = [
                rule for rule in self._rules if rule["id"] not in self._ignore
            ]

            self._rules, self._compiled = self._compile_pattern_rules(
                self._rules,
            )

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Load default PII detection rules.

        Loads the built-in PII pattern definitions from the common pattern
        directory.

        Returns:
            A list of PII rule definitions used by the detector.

        Raises:
            FileNotFoundError:
                If the default PII pattern file cannot be found.
        """
        return self._loader.load_patterns(
            PATTERNS_ROOT / "common" / "pii.yaml",
        )
