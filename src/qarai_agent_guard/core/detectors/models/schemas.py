from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class DetectionResult:
    """Unified detection output across all models and detectors."""

    detected: bool
    score: float
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)

