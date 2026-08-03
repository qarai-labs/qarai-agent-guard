from __future__ import annotations

from pathlib import Path
from typing import Any

from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
from qarai_agent_guard.core.helpers.detection_utils import normalize_language
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT

DEFAULT_LANGUAGE = "en"


class ModelReasoningDetector(BaseDetector):
    """Detect model reasoning leaks and prompt-injection attempts.

    This detector combines language-specific reasoning detection rules with
    shared XML injection patterns. Rules may be loaded from the built-in
    pattern repository or provided explicitly during initialization.

    Attributes:
        name: Unique detector identifier.
        default_message: Message returned when a detection occurs.
    """

    name = "model_reasoning"
    default_message = "Possible model reasoning or prompt injection detected"

    def __init__(
        self,
        *,
        lang: str = DEFAULT_LANGUAGE,
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        loader: PatternLoader | None = None,
        detector_type : str = "regex"
    ) -> None:
        """Initialize the model reasoning detector.

        Args:
            lang: Language code or alias used to select language-specific
                detection rules.
            patterns: Optional inline rules. When provided, these override
                the detector default rule loading.
            loader: Optional pattern loader instance. If omitted, a loader
                using the built-in pattern directory is created.

        Raises:
            TypeError:
                If ``lang`` is not a string or ``loader`` is not a
                ``PatternLoader`` instance.
            ValueError:
                If ``lang`` is empty or unsupported.
        """
        if not isinstance(lang, str):
            msg = f"lang must be str, got {type(lang).__name__}"
            raise TypeError(msg)

        if not lang.strip():
            msg = "lang must not be empty"
            raise ValueError(msg)

        if loader is not None and not isinstance(loader, PatternLoader):
            msg = f"loader must be PatternLoader or None, got {type(loader).__name__}"
            raise TypeError(msg)

        try:
            self._language_code = normalize_language(lang)
        except ValueError as exc:
            raise ValueError(f"Unsupported language code: '{lang}'") from exc

        super().__init__(
            lang=lang,
            patterns=patterns,
            pattern_paths=pattern_paths,
            loader=loader or PatternLoader(PATTERNS_ROOT),
            detector_type=detector_type
        )

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Load the detector default pattern rules.

        The default rule set consists of:

        - Language-specific model reasoning patterns.
        - Shared XML injection detection patterns.

        Returns:
            Combined pattern rule definitions used by the detector.

        Raises:
            FileNotFoundError:
                If a required pattern file cannot be found.
        """
        language_path = (
            PATTERNS_ROOT / "languages" / self._language_code / "model_reasoning.yaml"
        )

        xml_path = PATTERNS_ROOT / "common" / "xml_injection.yaml"

        rules = self._loader.load_patterns(language_path)
        rules.extend(self._loader.load_patterns(xml_path))

        return rules
