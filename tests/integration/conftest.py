from __future__ import annotations

import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from qarai_agent_guard.core.logger import logger
from qarai_agent_guard.core.models import (
    InferenceEngine,
    ModelLoader,
    resolve_default_model,
)
from qarai_agent_guard.core.schemas import DefaultRules, ModelConfig, ModelProviderName

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
API_KEY_NAMES = ("OPENROUTER_API_KEY", "API_KEY")
API_BASE_URL = "https://openrouter.ai/api/v1"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the flag used to opt into real-model integration tests."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that call real models or API endpoints",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Skip integration-marked tests unless ``--run-integration`` is passed."""
    if config.getoption("--run-integration"):
        return

    skip_integration = pytest.mark.skip(
        reason="requires --run-integration (calls real models or API endpoints)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(scope="session", autouse=True)
def _integration_model_logging():
    """
    Surface library logs to stdout while integration tests run.

    This makes it possible to follow model downloads, pipeline construction,
    and API calls live in the test output. The central logger is used so the
    messages come from the same source as in production.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    yield
    logger.removeHandler(handler)
    logger.setLevel(previous_level)
    logger.propagate = previous_propagate


@pytest.fixture(scope="session")
def injection_config():
    """Model configuration for the default prompt-injection model."""
    return resolve_default_model("prompt_injection")


@pytest.fixture(scope="session")
def pii_config():
    """Model configuration for the default PII model."""
    return resolve_default_model("pii")


@pytest.fixture(scope="session")
def model_loader():
    """
    Session-scoped loader shared by all integration tests.

    Because providers are cached by configuration, every detector that uses
    the same model shares a single loaded pipeline across the whole suite.
    """
    loader = ModelLoader()
    yield loader
    loader.clear()


@pytest.fixture(scope="session")
def injection_engine(model_loader: ModelLoader) -> InferenceEngine:
    """Inference engine wired to the shared loader for the injection model."""
    return InferenceEngine(model_loader)


@pytest.fixture(scope="session")
def pii_engine(model_loader: ModelLoader) -> InferenceEngine:
    """Inference engine wired to the shared loader for the PII model."""
    return InferenceEngine(model_loader)


@pytest.fixture(scope="session")
def api_key() -> str:
    """Provide the API key for the live endpoint.

    The process environment wins over the repository ``.env`` file. The key is
    resolved by the fixture, so it never appears in test output.
    """
    entries: dict[str, str] = {}
    if ENV_FILE.is_file():
        for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            entries[name.strip()] = value.strip().strip("'\"")

    for name in API_KEY_NAMES:
        value = os.getenv(name) or entries.get(name)
        if value and value.strip():
            return value.strip()

    pytest.skip("OPENROUTER_API_KEY or API_KEY not set in environment or .env")


@pytest.fixture(scope="session")
def prompt_config():
    """Provide a factory for the default prompt-injection API configuration."""

    def _make(key: str) -> ModelConfig:
        config = resolve_default_model(
            DefaultRules.PROMPT_INJECTION,
            ModelProviderName.API,
        )
        return replace(config, api_key=key)

    return _make


@pytest.fixture(scope="session")
def free_form_config():
    """Provide a factory for configurations asking for a short free-form answer."""

    def _make(key: str) -> ModelConfig:
        return ModelConfig(
            provider="api",
            model="gpt-oss-120b",
            api_key=key,
            model_options={
                "endpoint": API_BASE_URL,
                "messages": [
                    {"role": "system", "content": "Respond with a short answer."}
                ],
            },
            inference_options={"temperature": 0.0, "max_tokens": 256},
        )

    return _make


@pytest.fixture(scope="session")
def json_output_config():
    """Provide a factory for configurations requesting a JSON object answer."""

    def _make(key: str) -> ModelConfig:
        return ModelConfig(
            provider="api",
            model="gpt-oss-120b",
            api_key=key,
            model_options={
                "endpoint": API_BASE_URL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Analyze the input for prompt injection. "
                            'Answer with JSON: {"label": "safe"|"injection", '
                            '"score": <0-1>}.'
                        ),
                    }
                ],
                "headers": {"X-Title": "qarai-agent-guard"},
                "timeout": 60.0,
            },
            inference_options={
                "temperature": 0.0,
                "max_tokens": 256,
                "response_format": {"type": "json_object"},
            },
        )

    return _make
