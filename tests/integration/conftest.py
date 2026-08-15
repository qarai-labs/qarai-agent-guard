from __future__ import annotations

import logging
import sys

import pytest

from qarai_agent_guard.core.models.config import resolve_default_model
from qarai_agent_guard.core.models.engine import InferenceEngine
from qarai_agent_guard.core.models.loader import ModelLoader

MODEL_LOGGER = "qarai_agent_guard.core.models"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the flag used to opt into real-model integration tests."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that load real HuggingFace models",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Skip integration-marked tests unless ``--run-integration`` is passed."""
    if config.getoption("--run-integration"):
        return

    skip_integration = pytest.mark.skip(
        reason="requires --run-integration (loads real HuggingFace models)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(scope="session", autouse=True)
def _integration_model_logging() -> None:
    """
    Surface model loading logs to stdout while integration tests run.

    This makes it possible to follow model downloads / pipeline construction
    live in the test output.
    """
    logger = logging.getLogger(MODEL_LOGGER)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    yield
    logger.removeHandler(handler)


@pytest.fixture(scope="session")
def injection_config():
    """Model configuration for the default prompt-injection model."""
    return resolve_default_model("prompt_injection")


@pytest.fixture(scope="session")
def pii_config():
    """Model configuration for the default PII model."""
    return resolve_default_model("pii")


@pytest.fixture(scope="session")
def model_loader() -> ModelLoader:
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
