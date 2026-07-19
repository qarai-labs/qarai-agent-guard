from __future__ import annotations

from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT


class SecretsDetector(BaseDetector):
    """Detect secrets, credentials, and sensitive token patterns.

    This detector scans payloads for known secret formats such as API keys,
    credentials, and other sensitive authentication material. Rules can be
    loaded from the built-in pattern repository or supplied explicitly.

    Attributes:
        name: Unique detector identifier.
        default_message: Message returned when secret material is detected.
    """

    name = "secrets"
    default_message = "Secret or credential material detected"

    def __init__(
        self,
        *,
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        loader: PatternLoader | None = None,
    ) -> None:
        """Initialize the secrets detector.

        Args:
            patterns: Optional inline secret detection rules. When provided,
                these replace the default rules loaded from the pattern
                repository.
            loader: Optional pattern loader instance. If omitted, a loader
                using the built-in pattern directory is created.

        Raises:
            TypeError:
                If ``loader`` is not a ``PatternLoader`` instance.
        """
        if loader is not None and not isinstance(loader, PatternLoader):
            msg = f"loader must be PatternLoader or None, got {type(loader).__name__}"
            raise TypeError(msg)

        super().__init__(
            lang="common",
            patterns=patterns,
            pattern_paths=pattern_paths,
            loader=loader or PatternLoader(PATTERNS_ROOT),
        )

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Load default secret detection rules.

        Loads the built-in secret pattern definitions from the common
        pattern directory.

        Returns:
            A list of secret rule definitions used by the detector.

        Raises:
            FileNotFoundError:
                If the default secret pattern file cannot be found.
        """
        return self._loader.load_patterns(
            PATTERNS_ROOT / "common" / "secrets.yaml",
        )
