from abc import ABC, abstractmethod
from typing import Any

from qarai_agent_guard.core.schemas.models import ModelConfig


class ModelProvider(ABC):
    """Provider boundary: lifecycle plus raw inference only."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config

    @abstractmethod
    def load(self) -> None: ...

    @abstractmethod
    def predict(self, text: str) -> Any: ...

    @abstractmethod
    def unload(self) -> None: ...
