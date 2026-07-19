from __future__ import annotations

from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader


class Detector(BaseDetector):
    """Generic detector with flexible pattern configuration.

    This detector does not provide a built-in rule set. Instead, callers
    configure it by supplying either inline pattern definitions or one or
    more YAML pattern files. It is intended for applications that require
    custom detection logic without implementing a dedicated detector
    subclass.

    Attributes:
        name: Unique detector identifier.
        default_message: Default message returned when a detection occurs.
    """

    name = "detector"
    default_message = "Pattern detected"

    def __init__(
        self,
        *,
        lang: str = "en",
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        loader: PatternLoader | None = None,
    ) -> None:
        """Initialize a configurable pattern detector.

        Either ``patterns`` or ``pattern_paths`` must be provided.

        Args:
            lang: Language identifier stored in detection metadata.
            patterns: Optional inline pattern rule definitions.
            pattern_paths: Optional paths to YAML files containing
                pattern rule definitions.
            loader: Optional pattern loader used to load YAML files.

        Raises:
            ValueError:
                If neither ``patterns`` nor ``pattern_paths`` is provided.
            TypeError:
                Propagated from ``BaseDetector`` when an argument has an
                invalid type.
            KeyError:
                Propagated from ``BaseDetector`` if a rule is missing a
                required field.
            re.error:
                Propagated from ``BaseDetector`` if a rule contains an
                invalid regular expression.
        """
        if patterns is None and pattern_paths is None:
            raise ValueError("Either 'patterns' or 'pattern_paths' must be provided.")

        super().__init__(
            lang=lang,
            patterns=patterns,
            pattern_paths=pattern_paths,
            loader=loader,
        )

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Return the detector default rules.

        Raises:
            NotImplementedError:
                This detector does not define built-in pattern rules.
        """
        raise NotImplementedError(
            "Detector does not define default pattern rules. "
            "Provide 'patterns' or 'pattern_paths' when creating "
            "an instance."
        )
