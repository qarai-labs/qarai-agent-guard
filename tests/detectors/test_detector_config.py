from __future__ import annotations

import pytest

from qarai_agent_guard.core.detectors.detector import Detector
from qarai_agent_guard.core.exceptions import ConfigurationError
from qarai_agent_guard.core.schemas.detector import (
    CombinationStrategy,
    DefaultRules,
    DetectorType,
)

# Default configuration


def test_default_detector_type_is_regex():
    """Uses regex detection when no detector type is specified."""
    detector = Detector(default_rules="pii")

    assert detector.detector_type is DetectorType.REGEX


def test_default_combination_strategy_is_any():
    """Uses ANY as the default combination strategy."""
    detector = Detector(default_rules="secrets")

    assert detector.combination_strategy is CombinationStrategy.ANY


def test_default_rule_strategy_is_precedence():
    """Uses precedence as the default rule strategy."""
    detector = Detector(default_rules="pii")

    assert detector._rule_strategy == "precedence"


# Enum and value normalization


@pytest.mark.parametrize(
    "detector_type",
    list(DetectorType),
)
def test_detector_type_is_normalized(detector_type):
    """Converts a detector type value into its corresponding enum."""
    kwargs = (
        {
            "patterns": [
                {
                    "id": "x",
                    "name": "X",
                    "severity": "low",
                    "pattern": "x",
                }
            ]
        }
        if detector_type is DetectorType.REGEX
        else {"default_rules": "pii"}
    )

    detector = Detector(
        detector_type=detector_type.value,
        **kwargs,
    )

    assert detector.detector_type is detector_type


@pytest.mark.parametrize(
    "rule_set",
    list(DefaultRules),
)
def test_packaged_default_rules_create_regex_detectors(rule_set):
    """Creates a regex detector when a packaged rule set is selected."""
    detector = Detector(default_rules=rule_set)

    assert detector.detector_type is DetectorType.REGEX
    assert detector.default_rules is rule_set


@pytest.mark.parametrize(
    "strategy",
    list(CombinationStrategy),
)
def test_combination_strategy_is_normalized(strategy):
    """Converts a combination strategy value into its corresponding enum."""
    detector = Detector(
        detector_type="mixed",
        default_rules="prompt_injection",
        combination_strategy=strategy.value,
    )

    assert detector.combination_strategy is strategy


@pytest.mark.parametrize(
    "lang",
    ["en", "EN", "Fr", "AR", "ar"],
)
def test_language_is_normalized(lang):
    """Normalizes supported language codes to lowercase."""
    detector = Detector(
        default_rules="pii",
        lang=lang,
    )

    assert detector._language == lang.lower()


@pytest.mark.parametrize(
    "strategy",
    ["precedence", "extend"],
)
def test_valid_rule_strategy_is_accepted(strategy):
    """Accepts each supported rule strategy without modification."""
    detector = Detector(
        default_rules="pii",
        rule_strategy=strategy,
    )

    assert detector._rule_strategy == strategy


# Invalid configuration


@pytest.mark.parametrize(
    "detector_type",
    ["bogus", "regex2", "MODELX", 42, None],
)
def test_invalid_detector_type_is_rejected(detector_type):
    """Rejects unsupported detector type values."""
    with pytest.raises(ConfigurationError):
        Detector(
            detector_type=detector_type,
            default_rules="pii",
        )

    with pytest.raises(ConfigurationError):
        Detector(
            detector_type=detector_type,
            default_rules="prompt_injection",
        )


@pytest.mark.parametrize(
    "default_rules",
    ["invalid", 12],
)
def test_invalid_default_rules_are_rejected(default_rules):
    """Rejects unsupported default rule set values."""
    with pytest.raises(ConfigurationError):
        Detector(default_rules=default_rules)


@pytest.mark.parametrize(
    "strategy",
    ["bogus", "anyone", "", 12],
)
def test_invalid_combination_strategy_is_rejected(strategy):
    """Rejects unsupported combination strategy values."""
    with pytest.raises(ConfigurationError):
        Detector(
            default_rules="pii",
            combination_strategy=strategy,
        )


@pytest.mark.parametrize(
    "strategy",
    ["bad", None],
)
def test_invalid_rule_strategy_is_rejected(strategy):
    """Rejects unsupported rule strategy values."""
    with pytest.raises(ConfigurationError):
        Detector(
            default_rules="pii",
            rule_strategy=strategy,
        )


@pytest.mark.parametrize(
    "model",
    [
        "not-a-model",
        123,
        {"provider": "huggingface", "model": "m"},
        object(),
    ],
)
def test_invalid_model_config_is_rejected(model):
    """Rejects model configurations with invalid types or structure."""
    with pytest.raises(ConfigurationError):
        Detector(
            default_rules="pii",
            model=model,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"detector_type": "model"},
        {
            "detector_type": "model",
            "default_rules": "secrets",
        },
        {
            "detector_type": "model",
            "default_rules": None,
        },
    ],
)
def test_model_detector_requires_model_configuration(kwargs):
    """Rejects model detectors that cannot resolve a model configuration."""
    with pytest.raises(ConfigurationError):
        Detector(**kwargs)


def test_mixed_detector_requires_model_configuration():
    """Rejects mixed detectors configured without a model."""
    rule = {
        "id": "x",
        "name": "x",
        "severity": "low",
        "pattern": "x",
    }

    with pytest.raises(ConfigurationError):
        Detector(
            detector_type="mixed",
            patterns=[rule],
        )


@pytest.mark.parametrize(
    "lang",
    ["xx", "es", ""],
)
def test_unsupported_language_is_rejected(lang):
    """Rejects language codes that are not supported."""
    with pytest.raises(ValueError):
        Detector(
            default_rules="pii",
            lang=lang,
        )


@pytest.mark.parametrize(
    "lang",
    [None, 42],
)
def test_non_string_language_is_rejected(lang):
    """Rejects language values that are not strings."""
    with pytest.raises(TypeError):
        Detector(
            default_rules="pii",
            lang=lang,
        )


# Detector-specific initialization


def test_regex_detector_does_not_create_model_engine():
    """Keeps the model engine unset for regex-only detectors."""
    detector = Detector(default_rules="pii")

    assert detector._model_engine is None


def test_model_detector_creates_model_engine():
    """Creates model infrastructure for model detectors."""
    detector = Detector(
        detector_type="model",
        default_rules="pii",
    )

    assert detector._model_engine is not None
    assert detector._rules == []
    assert detector._compiled == []


def test_explicit_inference_engine_is_used(
    fake_engine,
    model_config,
    model_result,
):
    """Uses an explicitly supplied inference engine instance."""
    engine = fake_engine(model_result(False))

    detector = Detector(
        detector_type="model",
        model=model_config,
        inference_engine=engine,
    )

    assert detector._model_engine is engine


def test_valid_model_config_is_accepted(model_config):
    """Stores a valid model configuration unchanged."""
    detector = Detector(
        detector_type="model",
        model=model_config,
    )

    assert detector._model_config is model_config


def test_model_config_provider_is_normalized(model_config):
    """Normalizes the configured model provider to its enum value."""
    detector = Detector(
        detector_type="model",
        model=model_config,
    )

    assert detector._model_config.provider.value == "huggingface"


# Rule requirements


def test_regex_detector_requires_rules():
    """Rejects regex detectors when no rules are configured."""
    with pytest.raises(ConfigurationError):
        Detector(detector_type="regex")


def test_mixed_detector_requires_rules_even_with_model(model_config):
    """Rejects mixed detectors that have a model but no rules."""
    with pytest.raises(ConfigurationError):
        Detector(
            detector_type="mixed",
            model=model_config,
        )


def test_mixed_detector_requires_both_rules_and_model():
    """Rejects mixed detectors when both rules and model are missing."""
    with pytest.raises(ConfigurationError):
        Detector(detector_type="mixed")


def test_regex_detector_accepts_empty_pattern_list_as_explicit_rules():
    """Allows an explicit empty pattern list as a deliberate no-rule configuration."""
    detector = Detector(
        detector_type="regex",
        patterns=[],
    )

    assert detector._rules == []


def test_default_rules_none_is_accepted_with_explicit_patterns():
    """Allows custom patterns when packaged default rules are disabled."""
    rule = {
        "id": "custom_rule",
        "name": "Custom Rule",
        "severity": "medium",
        "pattern": "confidential",
    }

    detector = Detector(
        default_rules=None,
        patterns=[rule],
    )

    assert detector.default_rules is None
    assert detector._rules == [rule]


# Model resolution precedence


def test_explicit_model_takes_precedence_over_default_rules_model(
    model_config,
):
    """Prefers an explicitly supplied model over a library default model."""
    detector = Detector(
        detector_type="model",
        default_rules="prompt_injection",
        model=model_config,
    )

    assert detector._model_config is model_config


def test_default_rules_resolve_library_default_model_when_none_given():
    """Resolves the library model associated with the selected default rules."""
    detector = Detector(
        detector_type="model",
        default_rules="prompt_injection",
    )

    assert detector._model_config is not None


def test_model_detector_without_default_rules_or_model_is_rejected():
    """Rejects model detectors that have no model resolution source."""
    with pytest.raises(ConfigurationError):
        Detector(detector_type="model")


# Language edge cases


@pytest.mark.parametrize(
    "lang",
    ["  en  ", "en\n", "\ten"],
)
def test_language_with_surrounding_whitespace_is_rejected_or_normalized(lang):
    """Pins the current behavior for whitespace-padded language codes."""
    try:
        detector = Detector(default_rules="pii", lang=lang)
    except ValueError:
        return

    assert detector._language == lang.strip().lower()


# Detector type and rule interaction


def test_model_only_detector_ignores_pattern_paths(model_config):
    """Keeps model-only detectors free from regex rule state."""
    detector = Detector(
        detector_type="model",
        model=model_config,
    )

    assert detector._rules == []
    assert detector._compiled == []


def test_regex_detector_with_default_rules_prompt_injection_has_no_model_config():
    """Keeps regex detectors independent from prompt-injection model defaults."""
    detector = Detector(default_rules="prompt_injection")

    assert detector._model_engine is None
    assert detector._model_config is None


@pytest.mark.parametrize(
    "strategy",
    ["all", "any", "precedence"],
)
def test_combination_strategy_is_normalized_for_regex_detector(strategy):
    """Normalizes combination strategies even when regex detection does not use them."""
    detector = Detector(
        default_rules="pii",
        combination_strategy=strategy,
    )

    assert detector.combination_strategy.value == strategy


def test_combination_strategy_is_normalized_for_model_detector(
    model_config,
):
    """Normalizes combination strategies even when the detector is model-only."""
    detector = Detector(
        detector_type="model",
        model=model_config,
        combination_strategy="precedence",
    )

    assert detector.combination_strategy is CombinationStrategy.PRECEDENCE


# Validation precedence


def test_multiple_invalid_fields_raise_on_first_validated():
    """Reports the detector type error before validating other invalid fields."""
    with pytest.raises(ConfigurationError):
        Detector(
            detector_type="bogus",
            default_rules="also-bogus",
        )
