from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qarai_agent_guard.core.schemas.models import ModelDetectionResult

LANGUAGE_ALIASES: dict[str, str] = {
    "en": "en",
    "fr": "fr",
    "ar": "ar",
}

PATTERNS_ROOT = Path(__file__).resolve().parent.parent / "detectors" / "patterns"


@dataclass(slots=True)
class Match:
    """Single regex match produced by a pattern rule.

    Attributes:
        pattern_id (str): Stable identifier of the matched rule.
        pattern_name (str): Human-readable rule name.
        severity (str): Severity label from the pattern definition.
        match (str): Matched text span.
    """

    pattern_id: str
    pattern_name: str
    severity: str
    match: str


@dataclass(slots=True)
class DetectionResult:
    """Outcome of a detector inspection against one payload.

    Attributes:
        detector (str): Detector name that produced this result.
        matched (bool): Whether any pattern matched.
        message (str): Summary message when matched.
        matches (list[Match]): Individual pattern hits.
        metadata (dict[str, Any]): Extra context for policy evaluation.
    """

    detector: str
    matched: bool
    message: str = ""
    matches: list[Match] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    model_detection_result: ModelDetectionResult | None = None
