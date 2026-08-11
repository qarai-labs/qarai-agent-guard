from __future__ import annotations

import re

import pytest

from qarai_agent_guard.core.detectors.detector import Detector
from qarai_agent_guard.core.schemas.detection import PATTERNS_ROOT

# Rule source resolution


def test_inline_patterns_take_precedence_over_default_rules(hit_rules):
    """Uses inline patterns instead of packaged defaults under precedence."""
    detector = Detector(
        default_rules="pii",
        patterns=hit_rules,
    )

    assert [rule["id"] for rule in detector._rules] == [
        "instruction_override",
        "from_now_on",
    ]


def test_pattern_paths_take_precedence_over_default_rules(
    rule_yaml_factory,
):
    """Uses pattern paths instead of packaged defaults under precedence."""
    path = rule_yaml_factory(
        "path_only",
        "path-trigger",
    )

    detector = Detector(
        default_rules="pii",
        pattern_paths=[path],
    )

    assert [rule["id"] for rule in detector._rules] == [
        "path_only",
    ]


def test_default_rules_are_used_when_no_explicit_rules_exist(
    pii_rules,
):
    """Falls back to packaged default rules when no explicit rules exist."""
    detector = Detector(default_rules="pii")

    assert detector._rules == pii_rules


@pytest.mark.parametrize(
    ("strategy", "expected"),
    [
        ("precedence", []),
        (
            "extend",
            [
                "credit_card",
                "iban",
                "email",
                "phone_e164",
                "passport_number",
            ],
        ),
    ],
)
def test_empty_pattern_paths_are_handled(
    strategy,
    expected,
):
    """Handles an explicitly empty pattern-path collection per strategy."""
    detector = Detector(
        default_rules="pii",
        pattern_paths=[],
        rule_strategy=strategy,
    )

    assert [rule["id"] for rule in detector._rules] == expected


def test_empty_patterns_are_distinguished_from_none(pii_rules):
    """Distinguishes explicit empty patterns from omitted or null patterns."""
    explicit_empty = Detector(
        default_rules="pii",
        patterns=[],
    )

    assert explicit_empty._rules == []

    implicit_none = Detector(
        default_rules="pii",
    )

    assert implicit_none._rules == pii_rules

    explicit_none = Detector(
        default_rules="pii",
        patterns=None,
    )

    assert explicit_none._rules == pii_rules


# Rule extension strategy


def test_extend_combines_all_rule_sources(
    rule_yaml_factory,
    pii_rules,
    hit_rules,
):
    """Combines defaults, pattern paths, and inline patterns in source order."""
    path = rule_yaml_factory(
        "path_ext",
        "path-trigger",
    )

    detector = Detector(
        default_rules="pii",
        pattern_paths=[path],
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in pii_rules]
        + ["path_ext", "instruction_override", "from_now_on"]
    )


def test_extend_without_default_rules_uses_paths_and_patterns(
    rule_yaml_factory,
    hit_rules,
):
    """Extends pattern paths with inline patterns without packaged defaults."""
    path = rule_yaml_factory(
        "path_ext",
        "path-trigger",
    )

    detector = Detector(
        pattern_paths=[path],
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == [
        "path_ext",
        "instruction_override",
        "from_now_on",
    ]


def test_extend_without_paths_uses_default_and_patterns(
    pii_rules,
    hit_rules,
):
    """Extends packaged defaults with inline patterns when paths are absent."""
    detector = Detector(
        default_rules="pii",
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in pii_rules] + ["instruction_override", "from_now_on"]
    )


def test_extend_without_inline_patterns_uses_default_and_paths(
    rule_yaml_factory,
    pii_rules,
):
    """Extends packaged defaults with pattern-path rules without inline rules."""
    path = rule_yaml_factory(
        "path_ext",
        "path-trigger",
    )

    detector = Detector(
        default_rules="pii",
        pattern_paths=[path],
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in pii_rules] + ["path_ext"]
    )


def test_extend_combines_prompt_injection_defaults_with_patterns(
    en_prompt_rules,
    xml_rules,
    hit_rules,
):
    """Extends prompt-injection defaults with additional inline rules."""
    detector = Detector(
        default_rules="prompt_injection",
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in en_prompt_rules]
        + [rule["id"] for rule in xml_rules]
        + ["instruction_override", "from_now_on"]
    )


def test_extend_combines_prompt_injection_defaults_with_pattern_paths(
    rule_yaml_factory,
    en_prompt_rules,
    xml_rules,
):
    """Extends prompt-injection defaults with rules loaded from a path."""
    path = rule_yaml_factory(
        "path_ext_injection",
        "override-safety-guardrails",
    )

    detector = Detector(
        default_rules="prompt_injection",
        pattern_paths=[path],
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in en_prompt_rules]
        + [rule["id"] for rule in xml_rules]
        + ["path_ext_injection"]
    )


def test_precedence_prompt_injection_defaults_are_overridden_by_patterns(
    hit_rules,
):
    """Replaces prompt-injection defaults with inline patterns under precedence."""
    detector = Detector(
        default_rules="prompt_injection",
        patterns=hit_rules,
        rule_strategy="precedence",
    )

    assert [rule["id"] for rule in detector._rules] == [
        "instruction_override",
        "from_now_on",
    ]


def test_extend_with_default_rules_none_uses_only_patterns_and_paths(
    rule_yaml_factory,
    hit_rules,
):
    """Extends only explicit paths and patterns when defaults are disabled."""
    path = rule_yaml_factory(
        "path_only_ext",
        "exfiltrate-customer-data",
    )

    detector = Detector(
        default_rules=None,
        pattern_paths=[path],
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == [
        "path_only_ext",
        "instruction_override",
        "from_now_on",
    ]


# Multiple pattern paths


def test_multiple_pattern_paths_are_combined_in_order(
    rule_yaml_factory,
):
    """Loads multiple pattern paths while preserving their declared order."""
    first = rule_yaml_factory(
        "first_path",
        "leak-internal-credentials",
    )
    second = rule_yaml_factory(
        "second_path",
        "disable-content-filter",
    )

    detector = Detector(
        pattern_paths=[first, second],
    )

    assert [rule["id"] for rule in detector._rules] == [
        "first_path",
        "second_path",
    ]


def test_multiple_pattern_paths_extend_with_default_rules_and_patterns(
    rule_yaml_factory,
    pii_rules,
    hit_rules,
):
    """Preserves path order while extending defaults and inline patterns."""
    first = rule_yaml_factory(
        "first_path",
        "leak-internal-credentials",
    )
    second = rule_yaml_factory(
        "second_path",
        "disable-content-filter",
    )

    detector = Detector(
        default_rules="pii",
        pattern_paths=[first, second],
        patterns=hit_rules,
        rule_strategy="extend",
    )

    assert [rule["id"] for rule in detector._rules] == (
        [rule["id"] for rule in pii_rules]
        + [
            "first_path",
            "second_path",
            "instruction_override",
            "from_now_on",
        ]
    )


# Custom pattern loader


def test_custom_loader_is_used_for_pattern_paths(
    rule_yaml_factory,
    recording_loader,
):
    """Delegates pattern-path loading to the configured custom loader."""
    path = rule_yaml_factory(
        "via_loader",
        "loader-trigger",
    )

    Detector(
        pattern_paths=[path],
        loader=recording_loader,
    )

    assert recording_loader.calls == [path]


def test_custom_loader_receives_each_pattern_path_separately(
    rule_yaml_factory,
    recording_loader,
):
    """Passes each configured pattern path separately to the custom loader."""
    first = rule_yaml_factory(
        "first_path",
        "leak-internal-credentials",
    )
    second = rule_yaml_factory(
        "second_path",
        "disable-content-filter",
    )

    Detector(
        pattern_paths=[first, second],
        loader=recording_loader,
    )

    assert recording_loader.calls == [first, second]


def test_custom_loader_is_used_for_default_rules(
    recording_loader,
):
    """Delegates packaged default-rule loading to the custom loader."""
    Detector(
        default_rules="pii",
        loader=recording_loader,
    )

    assert recording_loader.calls == [PATTERNS_ROOT / "common" / "pii.yaml"]


def test_custom_loader_is_used_for_secrets_default_rules(
    recording_loader,
):
    """Loads packaged secrets rules through the configured loader."""
    Detector(
        default_rules="secrets",
        loader=recording_loader,
    )

    assert recording_loader.calls == [PATTERNS_ROOT / "common" / "secrets.yaml"]


def test_custom_loader_is_used_for_prompt_injection_default_rules(
    recording_loader,
):
    """Loads both prompt-injection rule files through the custom loader."""
    Detector(
        default_rules="prompt_injection",
        loader=recording_loader,
    )

    assert recording_loader.calls == [
        PATTERNS_ROOT / "languages" / "en" / "model_reasoning.yaml",
        PATTERNS_ROOT / "common" / "xml_injection.yaml",
    ]


# Language-specific default rule resolution


@pytest.mark.parametrize(
    ("lang", "expected_id"),
    [
        ("en", "instruction_override"),
        ("fr", "ignore_instructions"),
        ("ar", "ignore_security_policy"),
    ],
)
def test_prompt_injection_rules_are_language_specific(
    lang,
    expected_id,
):
    """Loads language-specific prompt-injection rules for each language."""
    detector = Detector(
        default_rules="prompt_injection",
        lang=lang,
    )

    ids = [rule["id"] for rule in detector._rules]

    assert expected_id in ids
    assert "xml_system_tags" in ids


@pytest.mark.parametrize(
    ("lang", "unexpected_id"),
    [
        ("en", "ignore_instructions"),
        ("fr", "instruction_override"),
        ("ar", "summarize_instructions"),
    ],
)
def test_prompt_injection_rules_do_not_cross_languages(
    lang,
    unexpected_id,
):
    """Keeps language-specific prompt-injection rules isolated by language."""
    detector = Detector(
        default_rules="prompt_injection",
        lang=lang,
    )

    ids = [rule["id"] for rule in detector._rules]

    assert unexpected_id not in ids


@pytest.mark.parametrize(
    "default_rules",
    ["pii", "secrets"],
)
def test_non_prompt_defaults_do_not_load_language_rules(
    default_rules,
    pii_rules,
    secrets_rules,
):
    """Loads non-prompt defaults without language-specific rule files."""
    detector = Detector(default_rules=default_rules)

    expected = pii_rules if default_rules == "pii" else secrets_rules

    assert [rule["id"] for rule in detector._rules] == [rule["id"] for rule in expected]


@pytest.mark.parametrize(
    "lang",
    ["EN", "Fr", "AR"],
)
def test_prompt_injection_default_rules_use_normalized_language(
    recording_loader,
    lang,
):
    """Uses the normalized language when resolving prompt-injection paths."""
    Detector(
        default_rules="prompt_injection",
        lang=lang,
        loader=recording_loader,
    )

    assert recording_loader.calls[0] == (
        PATTERNS_ROOT / "languages" / lang.lower() / "model_reasoning.yaml"
    )


# Rule compilation


def test_compile_pattern_rules_rejects_non_list():
    """Rejects rule collections that are not lists."""
    with pytest.raises(TypeError):
        Detector._compile_pattern_rules("not-a-list")


@pytest.mark.parametrize(
    "rule",
    ["alpha", 42, None, ("id", "name")],
)
def test_compile_pattern_rules_rejects_non_dict_rule(rule):
    """Rejects individual rules that are not dictionaries."""
    with pytest.raises(TypeError):
        Detector._compile_pattern_rules([rule])


@pytest.mark.parametrize(
    "missing",
    ["id", "name", "severity", "pattern"],
)
def test_compile_pattern_rules_rejects_missing_fields(missing):
    """Rejects rules missing any required schema field."""
    rule = {
        "id": "r",
        "name": "Rule",
        "severity": "low",
        "pattern": "x",
    }

    del rule[missing]

    with pytest.raises(KeyError):
        Detector._compile_pattern_rules([rule])


def test_compile_pattern_rules_rejects_invalid_regex():
    """Propagates regex compilation errors for malformed patterns."""
    with pytest.raises(re.error):
        Detector._compile_pattern_rules(
            [
                {
                    "id": "bad",
                    "name": "Bad",
                    "severity": "low",
                    "pattern": "(",
                }
            ]
        )


def test_compile_pattern_rules_error_message_includes_rule_id():
    """Includes the rule identifier when reporting regex compilation errors."""
    with pytest.raises(re.error, match="unclosed_bracket"):
        Detector._compile_pattern_rules(
            [
                {
                    "id": "unclosed_bracket",
                    "name": "Unclosed Bracket",
                    "severity": "low",
                    "pattern": "[a-z",
                }
            ]
        )


def test_compile_pattern_rules_error_message_uses_id_when_missing_name():
    """Uses the rule identifier when a malformed rule lacks its name."""
    rule = {
        "id": "malformed_rule",
        "severity": "low",
        "pattern": "trigger",
    }

    with pytest.raises(KeyError, match="malformed_rule"):
        Detector._compile_pattern_rules([rule])


def test_compile_pattern_rules_falls_back_to_index_when_id_missing():
    """Uses the rule index when a malformed rule lacks its identifier."""
    rule = {
        "name": "No Id Rule",
        "severity": "low",
        "pattern": "trigger",
    }

    with pytest.raises(KeyError, match=r"\b0\b"):
        Detector._compile_pattern_rules([rule])


def test_compile_pattern_rules_preserves_order():
    """Compiles patterns in the same order as their source rules."""
    rules = [
        {
            "id": "one",
            "name": "One",
            "severity": "low",
            "pattern": "aaa",
        },
        {
            "id": "two",
            "name": "Two",
            "severity": "low",
            "pattern": "bbb",
        },
        {
            "id": "three",
            "name": "Three",
            "severity": "low",
            "pattern": "ccc",
        },
    ]

    _, compiled = Detector._compile_pattern_rules(rules)

    assert [pattern.pattern for pattern in compiled] == [
        "aaa",
        "bbb",
        "ccc",
    ]

    assert compiled[0].search("bbb") is None
    assert compiled[1].search("ccc") is None


def test_compile_pattern_rules_returns_original_rules():
    """Returns the original rule collection alongside compiled patterns."""
    rules = [
        {
            "id": "one",
            "name": "One",
            "severity": "low",
            "pattern": "aaa",
        },
        {
            "id": "two",
            "name": "Two",
            "severity": "low",
            "pattern": "bbb",
        },
    ]

    returned, compiled = Detector._compile_pattern_rules(rules)

    assert returned is rules
    assert len(compiled) == len(rules)


def test_compile_pattern_rules_accepts_empty_list():
    """Returns empty compiled output when given no rules."""
    rules, compiled = Detector._compile_pattern_rules([])

    assert rules == []
    assert compiled == []


@pytest.mark.parametrize(
    "rules_fixture",
    ["pii_rules", "secrets_rules"],
)
def test_packaged_rules_compile_with_case_insensitive_dotall(
    request,
    rules_fixture,
):
    """Compiles packaged rules with case-insensitive and DOTALL flags."""
    rules = request.getfixturevalue(rules_fixture)

    _, compiled = Detector._compile_pattern_rules(rules)

    assert compiled
    assert all(pattern.flags & re.IGNORECASE for pattern in compiled)
    assert all(pattern.flags & re.DOTALL for pattern in compiled)


def test_compile_pattern_rules_dotall_matches_across_newlines():
    """Allows compiled patterns to match content spanning newlines."""
    rules = [
        {
            "id": "multiline_instruction_override",
            "name": "Multiline Instruction Override",
            "severity": "critical",
            "pattern": r"ignore.*instructions",
        }
    ]

    _, compiled = Detector._compile_pattern_rules(rules)

    payload = "ignore\nall previous\ninstructions"

    assert compiled[0].search(payload) is not None


def test_compile_pattern_rules_case_insensitive_matches_mixed_case():
    """Allows compiled patterns to match text regardless of casing."""
    rules = [
        {
            "id": "instruction_override",
            "name": "Instruction Override",
            "severity": "critical",
            "pattern": r"ignore\s+all\s+instructions",
        }
    ]

    _, compiled = Detector._compile_pattern_rules(rules)

    assert compiled[0].search("IGNORE ALL INSTRUCTIONS") is not None
    assert compiled[0].search("Ignore All Instructions") is not None


# Rule source validation


def test_regex_detector_raises_without_any_rule_source():
    """Rejects regex detectors that have no rule source configured."""
    from qarai_agent_guard.core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError):
        Detector(detector_type="regex")


def test_mixed_detector_raises_without_any_rule_source(model_config):
    """Rejects mixed detectors that have a model but no regex rules."""
    from qarai_agent_guard.core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError):
        Detector(
            detector_type="mixed",
            model=model_config,
        )


# Packaged rule content sanity checks


def test_secrets_rules_include_expected_ids(secrets_detector):
    """Ensures packaged secrets rules contain an AWS-related rule."""
    ids = [rule["id"] for rule in secrets_detector._rules]

    assert "aws_access_key" in ids or any("aws" in rule_id for rule_id in ids)


def test_secrets_detector_detects_aws_key_pattern(secrets_detector):
    """Confirms the packaged secrets rules detect a representative AWS key."""
    result = secrets_detector.inspect(
        "payload",
        "AKIAIOSFODNN7EXAMPLE",
        operation="input",
    )

    assert result.matched is True


def test_pii_rules_include_expected_ids(pii_detector):
    """Ensures packaged PII rules contain the core expected identifiers."""
    ids = [rule["id"] for rule in pii_detector._rules]

    assert {"email", "credit_card", "phone_e164"}.issubset(set(ids))
