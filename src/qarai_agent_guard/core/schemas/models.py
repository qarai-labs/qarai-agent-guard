from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from qarai_agent_guard.core.exceptions import ConfigurationError
from qarai_agent_guard.core.schemas.events import Severity


class ModelProviderName(StrEnum):
    HUGGINGFACE = "huggingface"


class ModelTask(StrEnum):
    """Supported HuggingFace task types.

    The value is the canonical task string passed to the underlying
    AutoModel class selector.

    Attributes
    ----------
    TEXT_CLASSIFICATION:
        Sequence-level classification (e.g. prompt-injection detection).
        Loaded with ``AutoModelForSequenceClassification``.
    TOKEN_CLASSIFICATION:
        Token-level labelling (e.g. PII / NER).
        Loaded with ``AutoModelForTokenClassification``.
    TEXT_GENERATION:
        Causal language modelling.
        Loaded with ``AutoModelForCausalLM``.
    TEXT2TEXT_GENERATION:
        Encoder-decoder generation (e.g. T5, BART).
        Loaded with ``AutoModelForSeq2SeqLM``.
    """

    TEXT_CLASSIFICATION = "text-classification"
    TOKEN_CLASSIFICATION = "token-classification"
    TEXT_GENERATION = "text-generation"
    TEXT2TEXT_GENERATION = "text2text-generation"


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Configuration for a model-based detector.

    Parameters
    ----------
    provider:
        Model hosting provider. Currently only ``"huggingface"`` is supported.
    model:
        Model identifier (e.g. a HuggingFace Hub repo name or local path).
    task:
        Task type that determines which ``AutoModel*`` class is loaded.
        Accepts a :class:`ModelTask` value or its string equivalent.
        Defaults to ``"text-classification"``.
    threshold:
        Confidence threshold in ``[0, 1]`` used by the default output
        formatter when interpreting raw confidence scores.
    hf_access_token:
        Optional HuggingFace Hub access token for private models.
    api_key:
        Optional API key (reserved for future providers).
    output_formatter:
        Optional callable ``(raw_output, config) -> ModelDetectionResult``
        used to convert the provider's raw output into a detection result.
    model_options:
        Keyword arguments forwarded to ``AutoModel*.from_pretrained()``.
    tokenizer_options:
        Keyword arguments forwarded to ``AutoTokenizer.from_pretrained()``.
    inference_options:
        Keyword arguments forwarded to the model's ``__call__`` / ``generate``
        invocation at inference time.
    options:
        *Deprecated.* Previously a single bag of miscellaneous options.
        Values are migrated to ``inference_options`` automatically during
        initialisation. A :class:`DeprecationWarning` is emitted when this
        field is supplied.
    """

    provider: ModelProviderName | str
    model: str
    task: ModelTask | str = ModelTask.TEXT_CLASSIFICATION
    threshold: float = 0.5
    hf_access_token: str | None = None
    api_key: str | None = None
    output_formatter: Callable[[Any, ModelConfig], ModelDetectionResult] | None = field(
        default=None, compare=False, hash=False, repr=False
    )
    model_options: dict[str, Any] | None = field(
        default=None, compare=False, hash=False
    )
    tokenizer_options: dict[str, Any] | None = field(
        default=None, compare=False, hash=False
    )
    inference_options: dict[str, Any] | None = field(
        default=None, compare=False, hash=False
    )
    # Deprecated — kept for backward compatibility only.
    options: dict[str, Any] | None = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "provider", ModelProviderName(self.provider))
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("provider must be one of: huggingface") from exc

        if not isinstance(self.model, str) or not self.model.strip():
            raise ConfigurationError("model must be a non-empty string")

        try:
            object.__setattr__(self, "task", ModelTask(self.task))
        except (TypeError, ValueError) as exc:
            valid = ", ".join(f'"{t.value}"' for t in ModelTask)
            raise ConfigurationError(f"task must be one of: {valid}") from exc

        if isinstance(self.threshold, bool) or not isinstance(
            self.threshold, int | float
        ):
            raise ConfigurationError("threshold must be a number in [0, 1]")
        if not 0 <= self.threshold <= 1:
            raise ConfigurationError("threshold must be a number in [0, 1]")

        if self.output_formatter is not None and not callable(self.output_formatter):
            raise ConfigurationError("output_formatter must be callable or None")

        for field_name in ("model_options", "tokenizer_options", "inference_options"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, dict):
                raise ConfigurationError(f"{field_name} must be a dict or None")

        # Migrate the deprecated `options` bag.
        if self.options is not None:
            if not isinstance(self.options, dict):
                raise ConfigurationError("options must be a dict or None")
            warnings.warn(
                "ModelConfig.options is deprecated. Use model_options, "
                "tokenizer_options, or inference_options instead.",
                DeprecationWarning,
                stacklevel=3,
            )
            # Fold deprecated options into inference_options (last-write wins for
            # keys that are also present in the explicit field).
            merged: dict[str, Any] = dict(self.options)
            if self.inference_options:
                merged.update(self.inference_options)
            object.__setattr__(self, "inference_options", merged)


@dataclass(slots=True)
class ModelDetectionResult:
    detected: bool
    score: float | None = None
    severity: Severity | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    entities: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.detected, bool):
            raise TypeError("detected must be bool")
        if self.severity is None:
            self.severity = Severity.CRITICAL if self.detected else Severity.LOW
        elif not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        if not isinstance(self.entities, list):
            raise TypeError("entities must be a list")
