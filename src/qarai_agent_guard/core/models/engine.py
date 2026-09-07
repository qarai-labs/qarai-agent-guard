from __future__ import annotations

import re
from typing import Any

from qarai_agent_guard.core.exceptions import (
    ModelFormatterError,
    ModelOutputError,
)
from qarai_agent_guard.core.models.loader import ModelLoader
from qarai_agent_guard.core.schemas.events import Severity
from qarai_agent_guard.core.schemas.models import (
    ModelConfig,
    ModelDetectionResult,
    ModelTask,
)

_POSITIVE_TEXT_MARKERS = ("true", "yes", "unsafe", "block", "malicious", "injection")
_NEGATIVE_TEXT_MARKERS = ("false", "no", "safe", "allow", "benign", "clean")

_POSITIVE_VERDICT_RE = re.compile(
    r"\b(?:" + "|".join(_POSITIVE_TEXT_MARKERS) + r")\b",
    re.IGNORECASE,
)
_NEGATIVE_VERDICT_RE = re.compile(
    r"\b(?:" + "|".join(_NEGATIVE_TEXT_MARKERS) + r")\b",
    re.IGNORECASE,
)


def _severity_for_score(score: float, threshold: float) -> Severity:
    if score < threshold:
        return Severity.LOW
    return Severity.CRITICAL


def _as_float(value: Any) -> float | None:
    """Best-effort coercion of numpy/torch scalar-likes to a native float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    item = getattr(value, "item", None)
    if callable(item):
        try:
            coerced = item()
        except Exception:
            return None
        if isinstance(coerced, int | float) and not isinstance(coerced, bool):
            return float(coerced)
    return None


class DefaultOutputFormatter:
    """Format model outputs into detection results.

    Recognizes, without any developer-supplied formatter:

    - ``bool`` values, where ``True`` indicates a detected issue.
    - Integer labels ``0`` and ``1``.
    - Floating-point confidence scores in ``[0, 1]``.
    - ``pipeline("text-classification")`` shape:
      ``{"label": str, "score": float}`` (or a one-item list of that dict).
      Detection is ``score >= config.threshold``.
    - ``pipeline("token-classification")`` shape:
      ``list[{"entity"/"entity_group": str, "score": float, ...}]``.
      Detection is true if any entity's score meets the threshold; overall
      score is the max entity score (``0.0`` if the list is empty).
    - ``pipeline("text-generation" | "text2text-generation")`` shape:
      ``[{"generated_text": str}]``. The text is matched case-insensitively
      against a small set of positive/negative verdict words
      (true/false, safe/unsafe, etc.).

    Models whose output doesn't match any of the above (custom heads,
    JSON-in-text, model-specific label semantics) must supply a custom
    ``output_formatter`` via :class:`ModelConfig`.
    """

    def format(
        self,
        raw: Any,
        config: ModelConfig,
    ) -> ModelDetectionResult:
        if isinstance(raw, bool):
            return ModelDetectionResult(
                detected=raw,
                score=1.0 if raw else 0.0,
                severity=Severity.CRITICAL if raw else Severity.LOW,
            )

        if isinstance(raw, int) and not isinstance(raw, bool) and raw in (0, 1):
            detected = bool(raw)
            return ModelDetectionResult(
                detected=detected,
                score=float(raw),
                severity=Severity.CRITICAL if detected else Severity.LOW,
            )

        score = _as_float(raw)
        if score is not None and 0.0 <= score <= 1.0:
            detected = score >= config.threshold
            return ModelDetectionResult(
                detected=detected,
                score=score,
                severity=_severity_for_score(score, config.threshold),
            )

        if self._looks_like_text_classification(raw):
            return self._format_text_classification(raw, config)

        if config.task is ModelTask.TOKEN_CLASSIFICATION and raw == []:
            return ModelDetectionResult(
                detected=False, score=0.0, severity=Severity.LOW
            )

        if self._looks_like_token_classification(raw):
            return self._format_token_classification(raw, config)

        if self._looks_like_generation(raw):
            return self._format_generation(raw, config)

        raise ModelOutputError(
            "Unsupported model output. Expected bool, 0/1, a confidence "
            "score in [0, 1], or a recognized HuggingFace pipeline shape "
            "(text-classification, token-classification, or generation). "
            "Provide a custom output_formatter for anything else."
        )

    # ------------------------------------------------------------------
    # Shape detection
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_text_classification(raw: Any) -> bool:
        item = raw[0] if isinstance(raw, list) and len(raw) == 1 else raw
        return isinstance(item, dict) and "label" in item and "score" in item

    @staticmethod
    def _looks_like_token_classification(raw: Any) -> bool:
        if not isinstance(raw, list):
            return False
        if len(raw) == 0:
            # Ambiguous (could be "no entities found" or "no generation").
            # Only treat as token-classification if config.task says so.
            return False
        first = raw[0]
        return isinstance(first, dict) and (
            "entity" in first or "entity_group" in first
        )

    @staticmethod
    def _looks_like_generation(raw: Any) -> bool:
        if not isinstance(raw, list) or len(raw) == 0:
            return False
        return isinstance(raw[0], dict) and "generated_text" in raw[0]

    # ------------------------------------------------------------------
    # Shape-specific formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _format_text_classification(
        raw: Any, config: ModelConfig
    ) -> ModelDetectionResult:
        item = raw[0] if isinstance(raw, list) else raw
        score = _as_float(item.get("score"))
        if score is None:
            raise ModelOutputError(
                f"text-classification output has a non-numeric score: {item!r}"
            )
        detected = score >= config.threshold
        return ModelDetectionResult(
            detected=detected,
            score=score,
            severity=_severity_for_score(score, config.threshold),
        )

    @staticmethod
    def _format_token_classification(
        raw: Any, config: ModelConfig
    ) -> ModelDetectionResult:
        scores: list[float] = []
        for item in raw:
            s = _as_float(item.get("score"))
            if s is not None:
                scores.append(s)

        if not scores:
            return ModelDetectionResult(
                detected=False, score=0.0, severity=Severity.LOW
            )

        top_score = max(scores)
        detected = top_score >= config.threshold
        return ModelDetectionResult(
            detected=detected,
            score=top_score,
            severity=_severity_for_score(top_score, config.threshold),
        )

    @staticmethod
    def _format_generation(
        raw: Any, config: ModelConfig
    ) -> ModelDetectionResult:
        text = str(raw[0].get("generated_text", "")).strip().lower()

        if _POSITIVE_VERDICT_RE.search(text):
            return ModelDetectionResult(
                detected=True, score=1.0, severity=Severity.CRITICAL
            )
        if _NEGATIVE_VERDICT_RE.search(text):
            return ModelDetectionResult(
                detected=False, score=0.0, severity=Severity.LOW
            )

        raise ModelOutputError(
            f"Could not interpret generated text as a verdict: {text!r}. "
            "Provide a custom output_formatter for models with "
            "non-standard verdict wording."
        )


_default_formatter = DefaultOutputFormatter()


class InferenceEngine:
    """Execute model inference and normalize model outputs."""

    def __init__(self, loader: ModelLoader | None = None) -> None:
        self.loader = loader or ModelLoader()

    def predict(
        self,
        text: str,
        config: ModelConfig,
    ) -> ModelDetectionResult:
        raw = self.loader.get(config).predict(text)

        try:
            if config.output_formatter is not None:
                result = config.output_formatter(raw, config)
            else:
                result = _default_formatter.format(raw, config)
        except ModelOutputError:
            raise
        except Exception as exc:
            raise ModelFormatterError(f"Failed to format model output: {exc}") from exc

        if not isinstance(result, ModelDetectionResult):
            raise ModelFormatterError(
                "Output formatter must return ModelDetectionResult"
            )

        return result
