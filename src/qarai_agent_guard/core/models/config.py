from __future__ import annotations

from typing import Any

from qarai_agent_guard.core.schemas.detector import DefaultRules
from qarai_agent_guard.core.schemas.events import Severity
from qarai_agent_guard.core.schemas.models import (
    ModelConfig,
    ModelDetectionResult,
)


def resolve_default_model(
    default_rules: DefaultRules | str | None,
) -> ModelConfig | None:
    """Resolve the default model configuration for a rule set.

    Maps supported library rule sets to their corresponding model
    configuration. The resolved configuration includes the model provider,
    model identifier, detection threshold, and output formatter required to
    normalize the model response.

    Currently, model-backed defaults are provided for:

    - :attr:`DefaultRules.PROMPT_INJECTION`
    - :attr:`DefaultRules.PII`

    Rule sets without a default model return ``None``.

    Parameters
    ----------
    default_rules:
        Rule set for which a default model should be resolved. Both
        :class:`DefaultRules` values and their string representations are
        accepted.

    Returns
    -------
    ModelConfig | None
        The default model configuration for the requested rule set, or
        ``None`` when no model is associated with the rule set or when
        ``default_rules`` is invalid.

    Notes
    -----
    Invalid rule values are intentionally treated as unresolved defaults
    rather than raising an exception. Configuration validation is handled
    by the detector layer.
    """
    if default_rules is None:
        return None

    try:
        rules = DefaultRules(default_rules)
    except (TypeError, ValueError):
        return None

    if rules is DefaultRules.PROMPT_INJECTION:
        return ModelConfig(
            provider="huggingface",
            model="deepset/deberta-v3-base-injection",
            task="text-classification",
            threshold=0.5,
            output_formatter=_format_default_injection,
        )

    if rules is DefaultRules.PII:
        return ModelConfig(
            provider="huggingface",
            model="SoelMgd/bert-pii-detection",
            task="token-classification",
            threshold=0.4,
            inference_options={"aggregation_strategy": "simple"},
            output_formatter=_format_default_pii,
        )

    return None


def _format_default_injection(
    raw: Any,
    config: ModelConfig,
) -> ModelDetectionResult:
    """Normalize the default prompt-injection model output.

    Expects the dict shape produced by :class:`HuggingFaceProvider` for
    ``task="text-classification"``:
    ``{"label": str, "score": float}``.

    A result is considered a detection when the predicted label belongs to a
    known injection class and the score meets ``config.threshold``.
    """
    item = raw[0] if isinstance(raw, list) and raw else raw

    if not isinstance(item, dict) or "label" not in item or "score" not in item:
        raise ValueError(
            "expected a text-classification dict with 'label' and 'score' keys"
        )

    label = str(item["label"]).upper()
    score = float(item["score"])

    detected = (
        label in {"INJECTION", "LABEL_1", "PROMPT_INJECTION"}
        and score >= config.threshold
    )

    return ModelDetectionResult(
        detected=detected,
        score=score if detected else 1 - score,
        severity=Severity.CRITICAL if detected else Severity.LOW,
        metadata={"raw_label": item["label"], "raw_score": score},
    )


def _format_default_pii(
    raw: Any,
    config: ModelConfig,
) -> ModelDetectionResult:
    """Normalize the default PII detection model output.

    Expects the list-of-dicts shape produced by :class:`HuggingFaceProvider`
    for ``task="token-classification"``.

    Each entity dict has at minimum ``"entity"`` (or ``"entity_group"``)
    and ``"score"`` keys.  Entities whose score is below ``config.threshold``
    or whose label is ``"O"`` are discarded.
    """
    if not isinstance(raw, list):
        raise ValueError("expected a list of token-classification entity dicts")

    entities = [
        item
        for item in raw
        if (
            isinstance(item, dict)
            # Support both pipeline-style "entity_group" and direct "entity" keys.
            and item.get("entity_group", item.get("entity", "O")) not in ("O", "")
            and float(item.get("score", 0)) >= config.threshold
        )
    ]

    score = max(
        (float(item["score"]) for item in entities),
        default=0.0,
    )
    detected = bool(entities)

    return ModelDetectionResult(
        detected=detected,
        score=score,
        severity=Severity.CRITICAL if detected else Severity.LOW,
        entities=entities,
        metadata={"detected_token_count": len(entities)},
    )
