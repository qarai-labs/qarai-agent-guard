from typing import Optional

from qarai_agent_guard.core.detectors.models.base import BaseModel
from qarai_agent_guard.core.detectors.models.registry import ModelRegistry
from qarai_agent_guard.core.detectors.models.schemas import DetectionResult



@ModelRegistry.register(task="prompt_injection", name="protectai_deberta")
class ProtectAIDebertaModel(BaseModel):
    """Wrapper for protectai/deberta-v3-base-prompt-injection / v2 models."""

    def __init__(self, model_name_or_path: Optional[str] = None, device: str = "cpu"):
        default_path = model_name_or_path or "protectai/deberta-v3-base-prompt-injection"
        super().__init__(model_name_or_path=default_path, device=device)
        self.tokenizer = None
        self.model = None

    def load(self) -> None:
        if self._is_loaded:
            return

        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name_or_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name_or_path)
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
            probs = torch.softmax(outputs.logits, dim=-1).squeeze(0)

        # Index 1 is INJECTION, Index 0 is BENIGN
        score = float(probs[1].item()) if probs.numel() > 1 else float(probs[0].item())
        is_detected = score >= 0.5

        return DetectionResult(
            detected=is_detected,
            score=score,
            label="prompt_injection" if is_detected else "clean",
            metadata={
                "model_name": self.name,
                "model_path": self.model_name_or_path,
                "raw_probs": probs.tolist(),
            },
        )