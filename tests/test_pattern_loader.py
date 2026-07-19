from __future__ import annotations

from pathlib import Path

import pytest

from qarai_agent_guard.core.loaders.pattern_loader import (
    PatternLoader,
    PatternLoaderError,
)
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT


def test_load_patterns_from_pii_yaml():
    loader = PatternLoader(PATTERNS_ROOT)
    rules = loader.load_patterns(PATTERNS_ROOT / "common" / "pii.yaml")
    assert len(rules) >= 5
    assert rules[0]["id"] == "credit_card"


def test_validate_rules_rejects_missing_fields(tmp_path: Path):
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text(
        "rules:\n  - id: broken\n",
        encoding="utf-8",
    )
    loader = PatternLoader(tmp_path)
    with pytest.raises(PatternLoaderError):
        loader.load_patterns(invalid)
