import pytest

from qarai_agent_guard.core.exceptions import ConfigurationError, ModelOutputError
from qarai_agent_guard.core.models.config import (
    _format_default_injection,
    _format_default_pii,
    resolve_default_model,
)
from qarai_agent_guard.core.models.engine import (
    DefaultOutputFormatter,
    _as_float,
    _severity_for_score,
)
from qarai_agent_guard.core.models.loader import ModelLoader
from qarai_agent_guard.core.schemas.events import Severity
from qarai_agent_guard.core.schemas.models import (
    ModelConfig,
    ModelTask,
)


@pytest.mark.parametrize("rule", ["prompt_injection", "pii", "secrets", None])
def test_default_model_resolution(rule):
    config = resolve_default_model(rule)
    if rule in ("secrets", None):
        assert config is None
    else:
        assert isinstance(config, ModelConfig)


@pytest.mark.parametrize("task", list(ModelTask))
def test_model_config_normalizes_all_supported_tasks(task):
    config = ModelConfig(provider="huggingface", model="model", task=task.value)
    assert config.task is task


@pytest.mark.parametrize(
    "kwargs",
    [
        {"provider": "other", "model": "m"},
        {"provider": "huggingface", "model": ""},
        {"provider": "huggingface", "model": "m", "threshold": 1.1},
    ],
)
def test_model_config_rejects_invalid_values(kwargs):
    with pytest.raises(ConfigurationError):
        ModelConfig(**kwargs)


@pytest.mark.parametrize(
    "value,expected", [(1, 1.0), (0.3, 0.3), (True, None), ("1", None)]
)
def test_score_helpers(value, expected):
    assert _as_float(value) == expected
    assert _severity_for_score(0.5, 0.5) is Severity.CRITICAL


@pytest.mark.parametrize(
    ("raw", "detected"),
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ({"label": "LABEL_0", "score": 0.9}, True),
        ([{"entity": "NAME", "score": 0.9}], True),
        ([{"generated_text": "safe"}], False),
        ([{"generated_text": "unsafe"}], True),
    ],
)
def test_default_formatter_supports_standard_huggingface_shapes(
    raw, detected, injection_config
):
    assert DefaultOutputFormatter().format(raw, injection_config).detected is detected


@pytest.mark.parametrize(
    "raw", [{"custom": "shape"}, [], [{"generated_text": "unknown"}]]
)
def test_default_formatter_rejects_unsupported_outputs(raw, injection_config):
    with pytest.raises(ModelOutputError):
        DefaultOutputFormatter().format(raw, injection_config)


@pytest.mark.parametrize(
    "label,score,detected",
    [("INJECTION", 0.5, True), ("LABEL_1", 0.9, True), ("OTHER", 0.9, False)],
)
def test_default_injection_formatter(label, score, detected, injection_config):
    result = _format_default_injection(
        {"label": label, "score": score}, injection_config
    )
    assert result.detected is detected


def test_default_pii_formatter_preserves_qualifying_entities(pii_config):
    result = _format_default_pii(
        [{"entity_group": "EMAIL", "score": 0.9, "start": 0, "end": 4}],
        pii_config,
    )
    assert result.detected and result.entities[0]["entity_group"] == "EMAIL"


def test_loader_key_shares_default_model_across_detection_options(injection_config):
    altered = ModelConfig(
        provider="huggingface",
        model=injection_config.model,
        task=injection_config.task,
        threshold=0.9,
    )
    assert ModelLoader._key(injection_config) == ModelLoader._key(altered)
