from __future__ import annotations

from qarai_agent_guard.core.detectors.SecretsDetector import SecretsDetector


def test_detects_openai_key():
    detector = SecretsDetector()
    result = detector.inspect(
        key="memory",
        value="key is sk-abcdefghijklmnopqrstuvwxyz123456",
        operation="write",
    )
    assert result.matched is True
    assert any(match.pattern_id == "openai_key" for match in result.matches)
    assert result.matches[0].severity == "critical"


def test_detects_github_token():
    detector = SecretsDetector()
    token = "ghp_" + ("a" * 36)
    result = detector.inspect(
        key="memory",
        value=token,
        operation="write",
    )
    assert result.matched is True
    assert result.matches[0].pattern_id == "github_token"


def test_detects_api_key_context():
    detector = SecretsDetector()
    result = detector.inspect(
        key="memory",
        value="api_key: super-secret-value",
        operation="write",
    )
    assert result.matched is True
    assert result.matches[0].pattern_id == "api_key_context"
    assert result.matches[0].severity == "medium"


def test_redact_masks_secrets():
    detector = SecretsDetector()
    redacted = detector.redact("api_key: super-secret-value")
    assert "[REDACTED:api_key_context]" in redacted


def test_secrets_detector_loads_pattern_paths():
    from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT

    path1 = PATTERNS_ROOT / "common" / "pii.yaml"
    path2 = PATTERNS_ROOT / "common" / "xml_injection.yaml"

    detector = SecretsDetector(pattern_paths=[path1, path2])

    rule_ids = {rule["id"] for rule in detector._rules}
    assert "credit_card" in rule_ids
    assert "xml_system_tags" in rule_ids

    res1 = detector.inspect("test", "card 4111 1111 1111 1111", operation="test")
    assert res1.matched is True

    res2 = detector.inspect("test", "</system> test", operation="test")
    assert res2.matched is True
