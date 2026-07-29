from typing import Optional

from qarai_agent_guard.core.detectors.models.base import BaseModel
from qarai_agent_guard.core.detectors.models.registry import ModelRegistry
from qarai_agent_guard.core.detectors.models.schemas import DetectionResult


@ModelRegistry.register(task="pii", name="distilbert_pii")
class DistilBertPIIModel(BaseModel):
    """Public, non-gated DistilBERT model for PII entity recognition."""

    def __init__(self, model_name_or_path: Optional[str] = None, device: str = "cpu"):
        default_path = model_name_or_path or "SoelMgd/bert-pii-detection"
        super().__init__(model_name_or_path=default_path, device=device)
        self.tokenizer = None
        self.model = None

    def load(self) -> None:
        if self._is_loaded:
            return

        from transformers import AutoModelForTokenClassification, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name_or_path)
        self.model = AutoModelForTokenClassification.from_pretrained(self.model_name_or_path)
        self.model.to(self.device)
        self.model.eval()
        self._is_loaded = True

    def predict(self, text: str) -> DetectionResult:
        if not self._is_loaded:
            self.load()

        import torch

        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)

        # Get predicted labels per token
        predictions = torch.argmax(probs, dim=-1).squeeze(0).tolist()
        
        # Check if any token is classified as non-O (i.e. PII entity detected)
        # Label 0 is usually 'O' (Outside / No PII)
        detected_entities = [p for p in predictions if p != 0]
        is_detected = len(detected_entities) > 0

        # Calculate confidence score as the highest entity probability found
        max_score = float(torch.max(probs[:, :, 1:]).item()) if is_detected else 0.0

        return DetectionResult(
            detected=is_detected,
            score=max_score,
            label="pii_detected" if is_detected else "clean",
            metadata={
                "model_name": self.name,
                "detected_token_count": len(detected_entities),
            },
        )