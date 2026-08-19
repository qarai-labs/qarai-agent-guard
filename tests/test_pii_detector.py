from __future__ import annotations

from qarai_agent_guard.core.detectors.PIIDetector import PIIDetector


def test_detects_credit_card():
    detector = PIIDetector()
    result = detector.inspect(
        key="memory",
        value="card 4111 1111 1111 1111",
        operation="write",
    )
    assert result.matched is True
    assert result.matches[0].pattern_id == "credit_card"
    assert result.matches[0].severity == "critical"


def test_detects_us_ssn():
    detector = PIIDetector()
    result = detector.inspect(
        key="memory",
        value="my ssn is 123-45-6789",
        operation="write",
    )
    assert result.matched is True
    assert any(match.pattern_id == "ssn_us" for match in result.matches)


def test_invalid_credit_card_is_not_detected():
    detector = PIIDetector()
    result = detector.inspect(
        key="memory",
        value="order id 4111 1111 1111 1112",
        operation="write",
    )
    assert result.matched is False


def test_detects_valid_card_after_invalid_candidate():
    detector = PIIDetector()
    result = detector.inspect(
        key="memory",
        value="ids 4111 1111 1111 1112 and 4111 1111 1111 1111",
        operation="write",
    )
    assert result.matched is True
    assert any(match.pattern_id == "credit_card" for match in result.matches)


def test_ignore_email():
    detector = PIIDetector(ignore=frozenset({"email"}))
    result = detector.inspect(
        key="memory",
        value="contact me at user@example.com",
        operation="write",
    )
    assert result.matched is False


def test_redact_masks_matches():
    detector = PIIDetector()
    redacted = detector.redact("card 4111 1111 1111 1111")
    assert "[REDACTED:credit_card]" in redacted


def test_redact_keeps_invalid_credit_card_like_numbers():
    detector = PIIDetector()
    redacted = detector.redact("order id 4111 1111 1111 1112")
    assert "[REDACTED:credit_card]" not in redacted
    assert "4111 1111 1111 1112" in redacted


def test_pii_detector_loads_pattern_paths():
    from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT

    path1 = PATTERNS_ROOT / "common" / "xml_injection.yaml"
    path2 = PATTERNS_ROOT / "common" / "secrets.yaml"

    detector = PIIDetector(pattern_paths=[path1, path2])

    rule_ids = {rule["id"] for rule in detector._rules}
    assert "xml_system_tags" in rule_ids
    assert "openai_key" in rule_ids

    res1 = detector.inspect("test", "</system> test", operation="test")
    assert res1.matched is True

    res2 = detector.inspect(
        "test", "sk-abcdefghijklmnopqrstuvwxyz123456", operation="test"
    )
    assert res2.matched is True
