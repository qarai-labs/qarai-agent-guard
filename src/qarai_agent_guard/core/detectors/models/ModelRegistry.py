from typing import Dict, Optional, Type
from qarai_agent_guard.core.detectors.models.BaseModel import BaseModel



class ModelRegistry:
    """Registry managing available model classes.
    
    Stores uninstantiated BaseModel subclasses indexed by task and model name.
    """

    _registry: Dict[str, Dict[str, Type[BaseModel]]] = {}

    @classmethod
    def register(cls, task: str, name: str):
        """Decorator to register a model class under a specific task and name."""
        def decorator(model_cls: Type[BaseModel]):
            if task not in cls._registry:
                cls._registry[task] = {}
            cls._registry[task][name.lower()] = model_cls
            model_cls.task = task
            model_cls.name = name.lower()
            return model_cls
        return decorator

    @classmethod
    def get(cls, task: str, name: str) -> Type[BaseModel]:
        """Retrieves an uninstantiated model class from the registry."""
        task_dict = cls._registry.get(task)
        if not task_dict:
            raise ValueError(f"No models registered for task '{task}'. Available tasks: {list(cls._registry.keys())}")
        
        model_cls = task_dict.get(name.lower())
        if not model_cls:
            raise ValueError(f"Model '{name}' not found for task '{task}'. Available models: {list(task_dict.keys())}")
            
        return model_cls

    @classmethod
    def list_models(cls, task: Optional[str] = None) -> Dict[str, list]:
        """Lists registered models, optionally filtered by task."""
        if task:
            return {task: list(cls._registry.get(task, {}).keys())}
        return {t: list(models.keys()) for t, models in cls._registry.items()}