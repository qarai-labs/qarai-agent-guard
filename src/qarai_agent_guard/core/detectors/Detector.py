from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from qarai_agent_guard.core.exceptions import ConfigurationError
from qarai_agent_guard.core.helpers.detection_utils import normalize_language
from qarai_agent_guard.core.helpers.stringify import StringifyError, _stringify
from qarai_agent_guard.core.loaders.pattern_loader import PatternLoader
from qarai_agent_guard.core.models import resolve_default_model
from qarai_agent_guard.core.models.engine import InferenceEngine
from qarai_agent_guard.core.schemas.detection import (
    PATTERNS_ROOT,
    DetectionResult,
    Match,
)
from qarai_agent_guard.core.schemas.detector import (
    CombinationStrategy,
    DefaultRules,
    DetectorType,
)
from qarai_agent_guard.core.schemas.models import ModelConfig, ModelDetectionResult

logger = logging.getLogger(__name__)


class Detector:
    """
    Configurable security detector for inspecting arbitrary input data.

    The detector supports three detection modes:

    - Regex-based detection using configurable pattern rules.
    - Model-based detection using an inference engine.
    - Mixed detection combining regex and model results.

    Parameters
    ----------
    lang:
        Language code used when resolving language-dependent default rules.
        Supported values are ``"en"``, ``"fr"``, and ``"ar"``.
        Defaults to ``"en"``.

    patterns:
        Optional list of inline regex rule definitions.

        When ``rule_strategy="precedence"``, inline patterns take precedence
        over ``pattern_paths`` and ``default_rules``.

        When ``rule_strategy="extend"``, inline patterns are combined with
        default rules and rules loaded from ``pattern_paths``.

    pattern_paths:
        Optional paths to files containing regex rule definitions.

        When ``rule_strategy="precedence"``, these rules are used when
        ``patterns`` are not provided and take precedence over
        ``default_rules``.

        When ``rule_strategy="extend"``, rules loaded from these paths are
        combined with default rules and inline patterns.

    loader:
        Optional pattern loader used to load rules from ``pattern_paths`` or
        library-provided rule files. A default loader is created when omitted.

    detector_type:
        Determines how input is inspected.

        ``"regex"``
            Only regex rules are evaluated.

        ``"model"``
            Only model inference is performed. Regex rules are not loaded.

        ``"mixed"``
            Both regex rules and model inference are performed.

    default_rules:
        Optional library-provided rule set. Supported values are
        ``"prompt_injection"``, ``"pii"``, and ``"secrets"``.

        Default rules are resolved according to ``rule_strategy``.

        For model-based detection, the selected default rule may also resolve
        the library's default model when no explicit ``model`` is provided.

    model:
        Optional model configuration used for model-based detection.

        An explicitly provided model takes precedence over a library default
        model resolved from ``default_rules``.

    rule_strategy:
        Determines how explicitly provided rules and library defaults are
        resolved.

        ``"precedence"``
            Explicit rules take precedence. Inline ``patterns`` are preferred
            over ``pattern_paths``, which are preferred over ``default_rules``.

        ``"extend"``
            Rules from ``default_rules``, ``pattern_paths``, and ``patterns``
            are combined.

    combination_strategy:
        Determines how regex and model results are combined when using
        ``detector_type="mixed"``.

        ``"any"``
            Detection succeeds when either regex or model detection succeeds.

        ``"all"``
            Detection succeeds only when both regex and model detection
            succeed.

        ``"precedence"``
            Uses precedence-based matching between regex and model results.

    Raises
    ------
    ConfigurationError
        If the detector configuration is invalid or required rules/model
        configuration cannot be resolved.
    """

    name = "detector"
    default_message = "Security check detected a possible issue"

    def __init__(
        self,
        *,
        lang: str = "en",
        name: str | None = None,
        patterns: list[dict[str, Any]] | None = None,
        pattern_paths: list[Path] | None = None,
        loader: PatternLoader | None = None,
        detector_type: DetectorType | str = DetectorType.REGEX,
        default_rules: DefaultRules | str | None = None,
        model: ModelConfig | None = None,
        rule_strategy: str = "precedence",
        combination_strategy: CombinationStrategy | str = CombinationStrategy.ANY,
        inference_engine: InferenceEngine | None = None,
    ) -> None:
        """
        Initialize a configurable security detector.

        Parameters
        ----------
        lang:
            Language used when resolving language-dependent rules.

        patterns:
            Optional inline regex rule definitions.

        pattern_paths:
            Optional paths to files containing regex rule definitions.

        loader:
            Optional pattern loader used to load regex rules.

        detector_type:
            Detection mode. Supported values are ``"regex"``, ``"model"``,
            and ``"mixed"``.

        default_rules:
            Optional library-provided rule set.

        model:
            Optional model configuration for model-based detection.

        rule_strategy:
            Strategy used to resolve explicit and default rules.

        combination_strategy:
            Strategy used to combine regex and model results in mixed mode.


        Raises
        ------
        ConfigurationError
            If the supplied configuration is invalid or required detection
            configuration cannot be resolved.
        """
        self.name = name or self.name
        self.detector_type = detector_type
        self.combination_strategy = combination_strategy

        self._validate_config(
            lang,
            default_rules,
            model,
            rule_strategy,
        )

        self._language = normalize_language(lang)
        self._rule_strategy = rule_strategy
        self._combination_strategy = CombinationStrategy(combination_strategy)
        if self.detector_type in (DetectorType.MODEL, DetectorType.MIXED):
            self._model_config = model or resolve_default_model(self.default_rules)
        else:
            self._model_config = None

        if (
            self.detector_type in (DetectorType.MODEL, DetectorType.MIXED)
            and self._model_config is None
        ):
            raise ConfigurationError(
                "model detection requires ModelConfig or a default_rules "
                "value with a library default model"
            )

        if (
            self.detector_type in (DetectorType.REGEX, DetectorType.MIXED)
            and patterns is None
            and pattern_paths is None
            and self.default_rules is None
        ):
            raise ConfigurationError(
                "regex detection requires patterns, pattern_paths, or default_rules"
            )

        if self.detector_type in (DetectorType.MODEL, DetectorType.MIXED):
            self._model_engine = inference_engine or InferenceEngine()
        else:
            self._model_engine = None

        self._loader = loader or PatternLoader(PATTERNS_ROOT)

        if self.detector_type is DetectorType.MODEL:
            self._rules: list[dict[str, Any]] = []
            self._compiled: list[re.Pattern[str]] = []
        else:
            resolved_rules = self._resolve_rules(
                patterns,
                pattern_paths,
                self._loader,
            )
            self._rules, self._compiled = self._compile_pattern_rules(resolved_rules)

    def inspect(
        self,
        key: str,
        value: Any,
        *,
        operation: str,
    ) -> DetectionResult:
        """
        Inspect a value for configured security threats.

        The method evaluates regex rules, model inference, or both depending
        on the configured detector type. In mixed mode, the results are
        combined according to ``combination_strategy``.

        Parameters
        ----------
        key:
            Logical name or path identifying the value being inspected.

        value:
            Arbitrary value to inspect. The value is converted to text before
            detection.

        operation:
            Name of the operation being performed on the value, such as
            ``"input"``, ``"output"``, or ``"tool_call"``.

        Returns
        -------
        DetectionResult
            Detection result containing the match status, matched rules,
            metadata, and optional model detection information.

        Raises
        ------
        TypeError
            If ``key`` or ``operation`` is not a string.

        ValueError
            If ``key`` or ``operation`` is empty.
        """
        self._validate_input(key, operation)

        try:
            text = _stringify(value)
        except StringifyError as exc:
            raise ValueError(
                f"value for '{key}' could not be stringified: {exc}"
            ) from exc

        if not text:
            return DetectionResult(
                detector=self.name,
                matched=False,
                metadata={
                    "language": self._language,
                    "operation": operation,
                    "hit_count": 0,
                },
            )

        hits: list[Match] = []

        if self.detector_type in (
            DetectorType.REGEX,
            DetectorType.MIXED,
        ):
            for rule, pattern in zip(self._rules, self._compiled):
                found = pattern.search(text)

                if found:
                    hits.append(
                        Match(
                            rule["id"],
                            rule["name"],
                            rule["severity"],
                            found.group(0),
                        )
                    )

        model_result: ModelDetectionResult | None = None

        if self.detector_type in (
            DetectorType.MODEL,
            DetectorType.MIXED,
        ):
            if self._model_engine is not None:
                model_result = self._model_engine.predict(
                    text,
                    self._model_config,
                )

        matched = self._combine_results(hits, model_result)

        message = self._build_message(
            key,
            matched,
            hits,
            model_result,
        )

        metadata: dict[str, Any] = {
            "language": self._language,
            "operation": operation,
            "hit_count": len(hits),
        }

        if model_result is not None:
            metadata["model"] = {
                "provider": self._model_config.provider.value,
                "name": self._model_config.model,
                "score": model_result.score,
                "severity": model_result.severity.value,
            }

        return DetectionResult(
            detector=self.name,
            matched=matched,
            message=message,
            matches=hits,
            metadata=metadata,
            model_detection_result=model_result,
        )

    def redact(
        self,
        value: Any,
        entities: (
            list[dict[str, Any]] | ModelDetectionResult | DetectionResult | None
        ) = None,
    ) -> str:
        """
        Redact sensitive values from input text.

        Regex-based rules are applied first. Model-detected entities are then
        replaced in reverse positional order so that earlier replacements do
        not invalidate the offsets of later entities.

        Parameters
        ----------
        value:
            Arbitrary value to redact. The value is converted to text using
            the library's stringification helper.

        entities:
            Optional model entities or detection result containing entities
            to redact. Supported values are:

            - A list of entity dictionaries.
            - A :class:`ModelDetectionResult`.
            - A :class:`DetectionResult`.

            Each entity is expected to contain ``start`` and ``end`` offsets.
            ``entity_group`` is used as the redaction label when available.

        Returns
        -------
        str
            Text with detected sensitive values replaced by redaction
            markers.

        Notes
        -----
        Regex rules are always applied when configured, regardless of whether
        ``entities`` is provided.
        """
        text = _stringify(value)

        if self.detector_type is DetectorType.MODEL and entities is None:
            logger.warning("redact() called on a model-only detector without entities")

        for rule, pattern in zip(self._rules, self._compiled):
            text = pattern.sub(
                f"[REDACTED:{rule['id']}]",
                text,
            )

        resolved_entities: list[dict[str, Any]] = []

        if entities is not None:
            if isinstance(entities, list):
                resolved_entities = entities

            elif hasattr(entities, "entities"):
                resolved_entities = entities.entities

            elif (
                hasattr(entities, "model_detection_result")
                and entities.model_detection_result is not None
            ):
                resolved_entities = (
                    getattr(
                        entities.model_detection_result,
                        "entities",
                        [],
                    )
                    or []
                )

        self._validate_entities(resolved_entities)

        for entity in sorted(
            resolved_entities,
            key=lambda item: item["start"],
            reverse=True,
        ):
            text = (
                text[: entity["start"]]
                + f"[REDACTED:{entity.get('entity_group', 'MODEL')}]"
                + text[entity["end"] :]
            )

        return text

    def _validate_config(
        self,
        lang: str,
        default_rules: DefaultRules | str | None,
        model: ModelConfig | None,
        rule_strategy: str,
    ) -> None:
        """
        Validate and normalize detector configuration.

        Parameters
        ----------
        lang:
            Language code used by the detector.

        default_rules:
            Default rule set to validate.

        model:
            Optional model configuration.

        rule_strategy:
            Rule resolution strategy.

        Raises
        ------
        ConfigurationError
            If any configuration value is invalid.
        """
        try:
            self.detector_type = DetectorType(self.detector_type)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "detector_type must be one of: regex, model, mixed"
            ) from exc

        try:
            self.default_rules = (
                DefaultRules(default_rules) if default_rules is not None else None
            )
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "default_rules must be one of: prompt_injection, pii, secrets, or None"
            ) from exc

        try:
            self.combination_strategy = CombinationStrategy(self.combination_strategy)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "combination_strategy must be one of: any, all, precedence"
            ) from exc

        if rule_strategy not in {"precedence", "extend"}:
            raise ConfigurationError("rule_strategy must be 'precedence' or 'extend'")

        if model is not None and not isinstance(model, ModelConfig):
            raise ConfigurationError("model must be a ModelConfig or None")

    def _load_default_rules(
        self,
        loader: PatternLoader,
    ) -> list[dict[str, Any]]:
        """
        Load rules associated with the configured default rule set.

        Parameters
        ----------
        loader:
            Pattern loader used to read the rule files.

        Returns
        -------
        list[dict[str, Any]]
            Loaded rule definitions. Returns an empty list when no default
            rule set is configured.
        """
        if self.default_rules is DefaultRules.PII:
            return loader.load_patterns(PATTERNS_ROOT / "common" / "pii.yaml")

        if self.default_rules is DefaultRules.SECRETS:
            return loader.load_patterns(PATTERNS_ROOT / "common" / "secrets.yaml")

        if self.default_rules is DefaultRules.PROMPT_INJECTION:
            rules = loader.load_patterns(
                PATTERNS_ROOT / "languages" / self._language / "model_reasoning.yaml"
            )
            rules.extend(
                loader.load_patterns(PATTERNS_ROOT / "common" / "xml_injection.yaml")
            )
            return rules

        return []

    def _resolve_rules(
        self,
        patterns: list[dict[str, Any]] | None,
        pattern_paths: list[Path] | None,
        loader: PatternLoader,
    ) -> list[dict[str, Any]]:
        """
        Resolve the final set of regex rules.

        Rule resolution depends on ``self._rule_strategy``.

        For ``"extend"``, rules are combined in the following order:

        1. Default rules.
        2. Rules loaded from ``pattern_paths``.
        3. Inline ``patterns``.

        For ``"precedence"``, the first explicitly configured source is used
        in the order ``patterns`` → ``pattern_paths`` → ``default_rules``.

        Parameters
        ----------
        patterns:
            Optional inline rule definitions.

        pattern_paths:
            Optional paths containing rule definitions.

        loader:
            Pattern loader used to load rules from files.

        Returns
        -------
        list[dict[str, Any]]
            Resolved regex rule definitions.
        """
        loaded_rules: list[dict[str, Any]] = []

        if pattern_paths:
            for path in pattern_paths:
                loaded_rules.extend(loader.load_patterns(path))

        default_rules = self._load_default_rules(loader)

        if self._rule_strategy == "extend":
            return [
                *default_rules,
                *loaded_rules,
                *(patterns or []),
            ]

        if patterns is not None:
            return patterns

        if pattern_paths is not None:
            return loaded_rules

        return default_rules

    def _combine_results(
        self,
        hits: list[Match],
        model_result: ModelDetectionResult | None,
    ) -> bool:
        """
        Combine regex and model detection results.

        Parameters
        ----------
        hits:
            Regex matches found during inspection.

        model_result:
            Optional result produced by model inference.

        Returns
        -------
        bool
            ``True`` when the configured detection strategy considers the
            input to contain a security issue; otherwise ``False``.
        """
        regex_detected = bool(hits)
        model_detected = bool(model_result and model_result.detected)

        if self.detector_type is DetectorType.REGEX:
            return regex_detected

        if self.detector_type is DetectorType.MODEL:
            return model_detected

        if self._combination_strategy is CombinationStrategy.ANY:
            return regex_detected or model_detected

        if self._combination_strategy is CombinationStrategy.ALL:
            return regex_detected and model_detected

        if self._combination_strategy is CombinationStrategy.PRECEDENCE:
            return regex_detected

        return False

    def _build_message(
        self,
        key: str,
        matched: bool,
        hits: list[Match],
        model_result: ModelDetectionResult | None,
    ) -> str:
        """
        Build a human-readable message for a detection result.

        Parameters
        ----------
        key:
            Logical name of the inspected value.

        matched:
            Whether the detector identified a potential security issue.

        hits:
            Regex matches produced during inspection.

        model_result:
            Optional model detection result.

        Returns
        -------
        str
            Detection message, or an empty string when no issue was detected.
        """
        if not matched:
            return ""

        if self.detector_type is DetectorType.REGEX:
            return self._build_regex_message(key)

        if self.detector_type is DetectorType.MODEL:
            return self._build_model_message(key)

        if hits and model_result and model_result.detected:
            return f"Security issue detected in '{key}'"

        if hits:
            return self._build_regex_message(key)

        return self._build_model_message(key)

    def _build_regex_message(self, key: str) -> str:
        """
        Build a message for regex-based detection.

        Parameters
        ----------
        key:
            Logical name of the inspected value.

        Returns
        -------
        str
            Human-readable regex detection message.
        """
        if self.default_rules is DefaultRules.PII:
            return f"PII pattern detected in '{key}'"

        if self.default_rules is DefaultRules.SECRETS:
            return f"Secrets pattern detected in '{key}'"

        if self.default_rules is DefaultRules.PROMPT_INJECTION:
            return f"Prompt injection pattern detected in '{key}'"

        return f"{self.default_message} in '{key}'"

    def _build_model_message(self, key: str) -> str:
        """
        Build a message for model-based detection.

        Parameters
        ----------
        key:
            Logical name of the inspected value.

        Returns
        -------
        str
            Human-readable model detection message.
        """
        rule_name = (
            self.default_rules.value.replace("_", " ")
            if self.default_rules
            else "issue"
        )

        return f"Model detected a potential {rule_name} in '{key}'"

    @staticmethod
    def _validate_input(
        key: str,
        operation: str,
    ) -> None:
        """
        Validate required inspection arguments.

        Parameters
        ----------
        key:
            Logical name of the value being inspected.

        operation:
            Name of the operation associated with the inspection.

        Raises
        ------
        TypeError
            If ``key`` or ``operation`` is not a string.

        ValueError
            If ``key`` or ``operation`` is empty or contains only whitespace.
        """
        if not isinstance(key, str):
            raise TypeError(f"key must be str, got {type(key).__name__}")

        if not key.strip():
            raise ValueError("key must not be empty")

        if not isinstance(operation, str):
            raise TypeError(f"operation must be str, got {type(operation).__name__}")

        if not operation.strip():
            raise ValueError("operation must not be empty")

    @staticmethod
    def _validate_entities(
        entities: list[dict[str, Any]],
    ) -> None:
        """
        Validate that redaction entities contain required offset fields.

        Parameters
        ----------
        entities:
            Entity dictionaries to validate.

        Raises
        ------
        ValueError
            If an entity is missing ``start`` or ``end``, or if the offsets
            are not integers, or if ``start`` is greater than ``end``.
        """
        for index, entity in enumerate(entities):
            if not isinstance(entity, dict):
                raise ValueError(
                    f"entities[{index}] must be a dict, got {type(entity).__name__}"
                )

            missing = {"start", "end"} - entity.keys()

            if missing:
                raise ValueError(
                    f"entities[{index}] is missing required "
                    f"field(s): {', '.join(sorted(missing))}"
                )

            start, end = entity["start"], entity["end"]

            if not isinstance(start, int) or not isinstance(end, int):
                raise ValueError(
                    f"entities[{index}] 'start' and 'end' must be "
                    f"int, got {type(start).__name__} and "
                    f"{type(end).__name__}"
                )

            if start > end:
                raise ValueError(
                    f"entities[{index}] has start ({start}) greater than end ({end})"
                )

    @staticmethod
    def _compile_pattern_rules(
        rules: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[re.Pattern[str]]]:
        """
        Validate and compile regex rule definitions.

        Each rule must contain the required fields ``id``, ``name``,
        ``severity``, and ``pattern``. Patterns are compiled using
        case-insensitive and DOTALL matching.

        Parameters
        ----------
        rules:
            List of regex rule definitions.

        Returns
        -------
        tuple[list[dict[str, Any]], list[re.Pattern[str]]]
            The original rule definitions and their compiled regex patterns.

        Raises
        ------
        TypeError
            If ``rules`` is not a list or an individual rule is not a
            dictionary.

        KeyError
            If a rule is missing one or more required fields.

        re.error
            If a rule contains an invalid regular expression.
        """
        if not isinstance(rules, list):
            raise TypeError(f"rules must be list, got {type(rules).__name__}")

        compiled: list[re.Pattern[str]] = []
        required = {"id", "name", "severity", "pattern"}

        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise TypeError(
                    f"rules[{index}] must be dict, got {type(rule).__name__}"
                )

            missing = required - rule.keys()

            if missing:
                raise KeyError(
                    f"Rule '{rule.get('id', index)}' is missing "
                    f"required field(s): {', '.join(sorted(missing))}"
                )

            try:
                compiled.append(
                    re.compile(
                        rule["pattern"],
                        re.IGNORECASE | re.DOTALL,
                    )
                )
            except re.error as exc:
                raise re.error(f"Invalid regex in rule '{rule['id']}': {exc}") from exc

        return rules, compiled
