from __future__ import annotations

import logging
from typing import Any

from qarai_agent_guard.core.exceptions import (
    ModelInferenceError,
    ModelLoadError,
)
from qarai_agent_guard.core.models.providers.base import ModelProvider
from qarai_agent_guard.core.schemas.models import ModelConfig, ModelTask

logger = logging.getLogger(__name__)

_TASK_TO_PIPELINE_NAME: dict[ModelTask, str] = {
    ModelTask.TEXT_CLASSIFICATION: "text-classification",
    ModelTask.TOKEN_CLASSIFICATION: "token-classification",
    ModelTask.TEXT_GENERATION: "text-generation",
    ModelTask.TEXT2TEXT_GENERATION: "text2text-generation",
}


class HuggingFaceProvider(ModelProvider):
    """Thin HuggingFace loading and inference adapter.

    Contract: given a ``ModelConfig``, load the requested HF task/model via
    ``transformers.pipeline()`` and return its raw output, unmodified.

    This provider deliberately does NOT normalize, reformat, or interpret
    output. Output shaping (thresholding, custom formatters, converting to
    ``ModelDetectionResult``) is the responsibility of ``InferenceEngine``.
    """

    def __init__(self, config: ModelConfig) -> None:
        super().__init__(config)
        self._pipeline: Any = None

    def load(self) -> None:
        if self._pipeline is not None:
            return
        try:
            from transformers import pipeline

            task: ModelTask = self.config.task
            pipeline_name = _TASK_TO_PIPELINE_NAME.get(task)
            if pipeline_name is None:
                raise ModelLoadError(
                    f"Unsupported task '{task.value}' for HuggingFaceProvider. "
                    "Set config.task to one of: "
                    + ", ".join(f'"{t.value}"' for t in _TASK_TO_PIPELINE_NAME)
                )

            model_opts: dict[str, Any] = dict(self.config.model_options or {})
            tok_opts: dict[str, Any] = dict(self.config.tokenizer_options or {})
            pipeline_opts: dict[str, Any] = dict(
                getattr(self.config, "pipeline_options", None) or {}
            )

            kwargs: dict[str, Any] = dict(pipeline_opts)
            kwargs.setdefault("model_kwargs", model_opts)
            kwargs.setdefault("tokenizer", self.config.model)
            if tok_opts:
                kwargs.setdefault("tokenizer_kwargs", tok_opts)
            if self.config.hf_access_token is not None:
                kwargs.setdefault("token", self.config.hf_access_token)

            device = getattr(self.config, "device", None)
            if device is not None:
                kwargs.setdefault("device", device)

            logger.info(
                "HuggingFaceProvider: loading model '%s' for task '%s'",
                self.config.model,
                pipeline_name,
            )
            self._pipeline = pipeline(
                task=pipeline_name,
                model=self.config.model,
                **kwargs,
            )
            logger.info(
                "HuggingFaceProvider: model '%s' ready for inference",
                self.config.model,
            )

        except ModelLoadError:
            raise
        except Exception as exc:
            raise ModelLoadError(
                f"Unable to load HuggingFace model '{self.config.model}': {exc}"
            ) from exc

    def predict(self, text: str) -> Any:
        """Run the pipeline and return its raw, unmodified output."""
        if not isinstance(text, str):
            raise ModelInferenceError("text must be a string")
        if self._pipeline is None:
            self.load()
        try:
            inf_opts: dict[str, Any] = dict(self.config.inference_options or {})
            return self._pipeline(text, **inf_opts)
        except ModelInferenceError:
            raise
        except Exception as exc:
            raise ModelInferenceError(f"HuggingFace inference failed: {exc}") from exc

    def unload(self) -> None:
        logger.info("HuggingFaceProvider: unloading model '%s'", self.config.model)
        self._pipeline = None
        try:
            import torch

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception:
            pass
