from __future__ import annotations

from qarai_agent_guard.core.helpers.detection_utils import (
    highest_match_severity,
    highest_result_severity,
    highest_results_severity,
    parse_severity,
)
from qarai_agent_guard.core.schemas.detection import DetectionResult, Match
from qarai_agent_guard.core.schemas.events import Severity


def test_parse_severity_normalizes_case():
    assert parse_severity("CRITICAL") == Severity.CRITICAL


def test_highest_match_severity_returns_max():
    matches = [
        Match("a", "A", "low", "x"),
        Match("b", "B", "critical", "y"),
        Match("c", "C", "medium", "z"),
    ]
    assert highest_match_severity(matches) == Severity.CRITICAL


def test_highest_result_severity_uses_matches_only():
    result = DetectionResult(
        detector="test",
        matched=True,
        matches=[
            Match("a", "A", "high", "x"),
        ],
    )
    assert highest_result_severity(result) == Severity.HIGH


def test_highest_results_severity_across_results():
    results = [
        DetectionResult(
            detector="one",
            matched=True,
            matches=[Match("a", "A", "medium", "x")],
        ),
        DetectionResult(
            detector="two",
            matched=True,
            matches=[Match("b", "B", "critical", "y")],
        ),
    ]
    assert highest_results_severity(results) == Severity.CRITICAL


def test_base_detector_loads_pattern_paths():
    from qarai_agent_guard.core.detectors.BaseDetector import BaseDetector
    from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT

    class DummyDetector(BaseDetector):
        name = "dummy"

        def _load_default_rules(self):
            return []

    path1 = PATTERNS_ROOT / "common" / "pii.yaml"
    path2 = PATTERNS_ROOT / "common" / "xml_injection.yaml"

    detector = DummyDetector(pattern_paths=[path1, path2])

    rule_ids = {rule["id"] for rule in detector._rules}
    assert "credit_card" in rule_ids
    assert "xml_system_tags" in rule_ids

    res1 = detector.inspect("test", "card 4111 1111 1111 1111", operation="test")
    assert res1.matched is True

    res2 = detector.inspect("test", "</system> test", operation="test")
    assert res2.matched is True
