from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from qarai_agent_guard import ModelReasoningDetector, PIIDetector
from qarai_agent_guard.core.detectors.models.inference import InferenceEngine
from qarai_agent_guard.core.detectors.models.loader import ModelLoader
from qarai_agent_guard.core.helpers.stringify import _stringify
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.schemas.detection import (
    PATTERNS_ROOT,
    DetectionResult,
    Match,
)


class BaseDetector(ABC):
    """Base detector that matches YAML-defined regex rules.

    Loads pattern rules from explicit lists, file paths, or detector-specific
    defaults, then scans stringified payloads for matches.
    """

    name: str
    default_message: str = "Pattern match detected"

    def __init__(
        self,
        *,
        lang: str = "en",
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        loader: PatternLoader | None = None,
        detector_type: str = "regex",
    ) -> None:
        """Initialize the detector and load its pattern rules.

        Pattern rules can be provided directly, loaded from one or more YAML
        files, or resolved from the detector's default rule set.

        Args:
            lang: Language code used when loading the default rule set.
            patterns: Inline pattern rule definitions. When provided, these
                take precedence over ``pattern_paths`` and the detector's
                default rules.
            pattern_paths: Paths to YAML files containing pattern rules.
                Used only when ``patterns`` is not provided.
            loader: Pattern loader instance. When omitted, a loader rooted at
                ``PATTERNS_ROOT`` is created.
            detector_type : Type of detector to use . 4 types are supported 
            "regex","model","model_first","regex_first"
            default is regex
        Raises:
            TypeError:
                - If ``lang`` is not a string.
                - If ``patterns`` is not a list of dictionaries.
                - If ``pattern_paths`` is not a list of ``Path`` objects.
                - If ``loader`` is not a ``PatternLoader``.
            ValueError:
                If ``lang`` is empty or contains only whitespace.
            NotImplementedError:
                If the detector subclass does not define ``name``.
        """
        if not isinstance(lang, str):
            msg = f"lang must be str, got {type(lang).__name__}"
            raise TypeError(msg)
        if not lang.strip():
            msg = "lang must not be empty"
            raise ValueError(msg)
        
        if detector_type not in ["regex","model","model_first","regex_first"]:
            msg = f"detector_type must be one of regex, model, model_first, regex_first, got {detector_type}"

        if patterns is not None:
            if not isinstance(patterns, list):
                msg = f"patterns must be list or None, got {type(patterns).__name__}"
                raise TypeError(msg)
            for index, rule in enumerate(patterns):
                if not isinstance(rule, dict):
                    msg = f"patterns[{index}] must be dict, got {type(rule).__name__}"
                    raise TypeError(msg)

        if pattern_paths is not None:
            if not isinstance(pattern_paths, list):
                msg = (
                    f"pattern_paths must be list or None, "
                    f"got {type(pattern_paths).__name__}"
                )
                raise TypeError(msg)
            for index, path in enumerate(pattern_paths):
                if not isinstance(path, Path):
                    msg = (
                        f"pattern_paths[{index}] must be Path, "
                        f"got {type(path).__name__}"
                    )
                    raise TypeError(msg)

        if loader is not None and not isinstance(loader, PatternLoader):
            msg = f"loader must be PatternLoader or None, got {type(loader).__name__}"
            raise TypeError(msg)

        if not getattr(self, "name", None):
            raise NotImplementedError(
                "Detector subclasses must define a 'name' attribute."
            )

        self._lang = lang
        self._loader = loader or PatternLoader(PATTERNS_ROOT)
        self._detector_type = detector_type

        if patterns is not None:
            self._rules = patterns
        elif pattern_paths is not None:
            self._rules = []
            for path in pattern_paths:
                self._rules.extend(self._loader.load_patterns(path))
        else:
            self._rules = self._load_default_rules()

        self._rules, self._compiled = self._compile_pattern_rules(self._rules)

        if self._detector_type in ["model","model_first","regex_first"]:
            self._model_loader = ModelLoader(default_device="cpu")
            self._model_engine = InferenceEngine(loader=self._model_loader)

    @abstractmethod
    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Return pattern rules when no explicit paths are supplied.

        Returns:
            list[dict[str, Any]]: Default YAML rule mappings for this detector.
        """

    def inspect(
        self,
        key: str,
        value: Any,
        *,
        operation: str,
    ) -> DetectionResult:
        """Scan a payload for configured regex patterns.

        Args:
            key (str): Memory key under inspection. Required.
            value (Any): Payload to inspect. Required.
            operation (str): CRUD operation name. Required.

        Returns:
            DetectionResult: Match summary and metadata for policy evaluation.

        Raises:
            TypeError: If ``key`` or ``operation`` is not a string.
            ValueError: If ``key`` or ``operation`` is empty.
        """
        if not isinstance(key, str):
            msg = f"key must be str, got {type(key).__name__}"
            raise TypeError(msg)
        if not key.strip():
            msg = "key must not be empty"
            raise ValueError(msg)
        if not isinstance(operation, str):
            msg = f"operation must be str, got {type(operation).__name__}"
            raise TypeError(msg)
        if not operation.strip():
            msg = "operation must not be empty"
            raise ValueError(msg)

        text = _stringify(value)
        if not text:
            return DetectionResult(
                detector=self.name,
                matched=False,
            )
        hits: list[Match] = []
        for index, pattern in enumerate(self._compiled):
            match = pattern.search(text)
            if not match:
                continue

            rule = self._rules[index]
            hits.append(
                Match(
                    pattern_id=rule["id"],
                    pattern_name=rule["name"],
                    severity=rule["severity"],
                    match=match.group(0),
                )
            )
        model_detection_result = None
        if self._detector_type!="regex":
            if isinstance(self, ModelReasoningDetector):
                task = "model_reasoning"
                model_detection_result = self._model_engine.predict(task=task,models="protectai_deberta",text=text)

            elif isinstance(self, PIIDetector):
                task = "pii"
                model_detection_result = self._model_engine.predict(task=task,models="distilbert_pii",text=text)
        

        if not hits:
            return DetectionResult(
                detector=self.name,
                matched=False,
                model_detection_result=model_detection_result
            )

        return DetectionResult(
            detector=self.name,
            matched=True,
            matches=hits,
            message=f"{self.default_message} in '{key}'",
            metadata={
                "language": self._lang,
                "hit_count": len(hits),
                "operation": operation,
            },
            model_detection_result=model_detection_result
        )

    def redact(self, value: Any) -> Any:
        """Replace matched pattern spans with redaction placeholders.

        Args:
            value (Any): Payload to redact. Required.

        Returns:
            Any: Redacted string representation of the payload.
        """
        text = _stringify(value)
        for index, pattern in enumerate(self._compiled):
            rule = self._rules[index]
            text = pattern.sub(
                f"[REDACTED:{rule['id']}]",
                text,
            )
        return text

    def _compile_pattern_rules(
        self,
        rules: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[re.Pattern[str]]]:
        """Validate and compile pattern rule definitions.

        Each rule must define the required metadata and a valid regular
        expression. Compiled patterns preserve the same ordering as the input
        rules.

        Args:
            rules: Pattern rule definitions to validate and compile.

        Returns:
            A tuple containing the original rule definitions and their
            compiled regular expression objects.

        Raises:
            TypeError:
                If ``rules`` is not a list or a rule is not a dictionary.
            KeyError:
                If a rule is missing one or more required fields.
            re.error:
                If a rule contains an invalid regular expression.
        """
        if not isinstance(rules, list):
            msg = f"rules must be list, got {type(rules).__name__}"
            raise TypeError(msg)

        required_keys = {"id", "name", "severity", "pattern"}

        compiled: list[re.Pattern[str]] = []

        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                msg = f"rules[{index}] must be dict, got {type(rule).__name__}"
                raise TypeError(msg)

            missing = required_keys - rule.keys()
            if missing:
                missing_keys = ", ".join(sorted(missing))
                msg = (
                    f"Rule '{rule.get('id', index)}' is missing required "
                    f"field(s): {missing_keys}"
                )
                raise KeyError(msg)

            try:
                compiled.append(
                    re.compile(
                        rule["pattern"],
                        re.IGNORECASE | re.DOTALL,
                    )
                )
            except re.error as exc:
                msg = f"Invalid regex in rule '{rule['id']}': {exc}"
                raise re.error(msg) from exc

        return rules, compiled
