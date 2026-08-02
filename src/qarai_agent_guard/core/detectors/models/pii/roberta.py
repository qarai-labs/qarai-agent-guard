from typing import List
from transformers import pipeline

from qarai_agent_guard.core.detectors.models.base import BaseModel
from qarai_agent_guard.core.detectors.models.registry import ModelRegistry
from qarai_agent_guard.core.detectors.models.schemas import ModelDetectionResult


@ModelRegistry.register("pii", "distilbert_pii")
class DistilBertPIIDetector(BaseModel):
    """Token-classification PII detector using a public DistilBERT PII model."""

    def __init__(
        self,
        model_name_or_path: str = "SoelMgd/bert-pii-detection",
        device: str = "cpu",
    ):
        super().__init__(model_name_or_path=model_name_or_path, device=device)
        self._ner_pipeline = None

    def load(self) -> None:
        if self.is_loaded:
            return

        # Uses standard aggregation_strategy to merge sub-word entity tokens
        self._ner_pipeline = pipeline(
            "token-classification",
            model=self.model_name_or_path,
            device=self.device,
            aggregation_strategy="simple",
        )
        self.set_is_loaded(True)

    def predict(self, text: str) -> ModelDetectionResult:
        if not self.is_loaded or self._ner_pipeline is None:
            self.load()

        entities: List[dict] = self._ner_pipeline(text)

        # Filter out non-PII or low-confidence tokens if necessary
        pii_entities = [
            entity for entity in entities 
            if entity.get("score", 0.0) >= 0.40 and entity.get("entity_group", "O") != "O"
        ]

        detected = len(pii_entities) > 0
        
        # Calculate maximum confidence score across detected entities
        max_score = (
            max([float(e["score"]) for e in pii_entities]) if detected else 0.0
        )

        detected_types = list({e["entity_group"] for e in pii_entities})

        return ModelDetectionResult(
            detected=detected,
            score=max_score,
            label="pii_detected" if detected else "clean",
            metadata={
                "detected_token_count": len(pii_entities),
                "detected_types": detected_types,
                "entities": pii_entities,
            },
        )