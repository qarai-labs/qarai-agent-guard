import abc
from typing import Optional
from qarai_agent_guard.core.detectors.models.schemas import ModelDetectionResult

class BaseModel(abc.ABC):
    """Abstract base class that all model wrappers must inherit from.
    
    Provides a standardized interface across HuggingFace, ONNX, PyTorch, 
    TensorFlow, or remote API wrappers.
    """

    name: str = "base_model"
    task: str = "generic"

    def __init__(self, model_name_or_path: Optional[str] = None, device: str = "cpu"):
        self.model_name_or_path = model_name_or_path
        self.device = device
        self._is_loaded = False

    @property
    def is_loaded(self) -> bool:
        """Returns True if model weights and tokenizer/assets are loaded into memory."""
        return self._is_loaded

    def set_is_loaded(self, value : bool) -> None:
        """Setter for is_loaded """
        self._is_loaded = value
        return;

    @abc.abstractmethod
    def load(self) -> None:
        """Loads weights, tokenizers, or establishes connection to remote endpoints.
        
        Must set self._is_loaded = True upon completion.
        """
        pass

    @abc.abstractmethod
    def predict(self, text: str) -> ModelDetectionResult:
        """Runs inference on input text and returns a normalized ModelDetectionResult."""
        pass