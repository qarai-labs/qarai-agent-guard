from transformers import pipeline
from qarai_agent_guard.core.detectors.models.base import BaseModel, ModelDetectionResult
from qarai_agent_guard.core.detectors.models.registry import ModelRegistry


@ModelRegistry.register("model_reasoning", "protectai_deberta")
class ProtectAIDebertaModel(BaseModel):
    """Prompt injection detector using deepset's public, ungated model."""

    def __init__(
        self,
        model_name_or_path: str = "deepset/deberta-v3-base-injection",
        device: str = "cpu",
    ):
        super().__init__(model_name_or_path="deepset/deberta-v3-base-injection", device=device)
        self._classifier = None

    def load(self) -> None:
        if self.is_loaded:
            return

        self._classifier = pipeline(
            "text-classification",
            model="deepset/deberta-v3-base-injection",
            device=self.device,
        )
        self.set_is_loaded(True)

    def predict(self, text: str) -> ModelDetectionResult:
        if not self.is_loaded or self._classifier is None:
            self.load()

        predictions = self._classifier(text)
        top_pred = predictions[0]

        raw_label = str(top_pred["label"]).upper()
        score = float(top_pred["score"])

        # Handles deepset output ('INJECTION' vs 'LEGIT') as well as standard ('LABEL_1')
        is_injection = raw_label in ["INJECTION", "LABEL_1", "PROMPT_INJECTION"]

        return ModelDetectionResult(
            detected=is_injection,
            score=score if is_injection else (1.0 - score),
            label="model_reasoning" if is_injection else "clean",
            metadata={"raw_label": top_pred["label"], "raw_score": score},
        )