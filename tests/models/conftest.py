import pytest

from qarai_agent_guard.core.models.config import resolve_default_model
from qarai_agent_guard.core.models.engine import InferenceEngine
from qarai_agent_guard.core.models.loader import ModelLoader
from qarai_agent_guard.core.models.providers.huggingface import HuggingFaceProvider


@pytest.fixture(scope="session")
def injection_config():
    return resolve_default_model("prompt_injection")


@pytest.fixture(scope="session")
def pii_config():
    return resolve_default_model("pii")


@pytest.fixture(scope="session")
def model_loader():
    loader = ModelLoader()
    yield loader
    loader.clear()


@pytest.fixture(scope="session")
def injection_provider(injection_config):
    provider = HuggingFaceProvider(injection_config)
    provider.load()
    return provider


@pytest.fixture(scope="session")
def inference_engine(model_loader):
    return InferenceEngine(model_loader)
