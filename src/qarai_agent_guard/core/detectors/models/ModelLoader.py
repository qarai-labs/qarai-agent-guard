import threading
from typing import Dict, Optional

from qarai_agent_guard.core.detectors.models.BaseModel import BaseModel
from qarai_agent_guard.core.detectors.models.ModelRegistry import ModelRegistry

class ModelLoader:
    """Thread-safe singleton managing model instances and memory caching."""

    def __init__(self, default_device: str = "cpu"):
        self.default_device = default_device
        self._cache: Dict[str, BaseModel] = {}
        self._lock = threading.Lock()

    def _get_cache_key(self, task: str, name: str, device: str) -> str:
        return f"{task}:{name.lower()}:{device}"

    def get_model(
        self,
        task: str,
        name: str,
        device: Optional[str] = None,
        model_name_or_path: Optional[str] = None,
    ) -> BaseModel:
        """Loads and returns a cached model instance.
        
        Instantiates and loads weights lazily on first access.
        """
        target_device = device or self.default_device
        cache_key = self._get_cache_key(task, name, target_device)

        if cache_key in self._cache:
            return self._cache[cache_key]

        with self._lock:
            # Double-check inside lock
            if cache_key in self._cache:
                return self._cache[cache_key]

            model_cls = ModelRegistry.get(task, name)
            model_instance = model_cls(
                model_name_or_path=model_name_or_path,
                device=target_device
            )
            model_instance.load()
            self._cache[cache_key] = model_instance
            return model_instance

    def clear_cache(self) -> None:
        """Clears all cached model instances from memory."""
        with self._lock:
            self._cache.clear()