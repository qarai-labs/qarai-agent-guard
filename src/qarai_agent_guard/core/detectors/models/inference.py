from typing import List, Optional, Union

from qarai_agent_guard.core.detectors.models.loader import ModelLoader
from qarai_agent_guard.core.detectors.models.schemas import DetectionResult


class InferenceEngine:
    """High-level interface used by detectors to run model predictions."""

    def __init__(self, loader: Optional[ModelLoader] = None, default_device: str = "cpu"):
        self.loader = loader or ModelLoader(default_device=default_device)

    def predict(
        self,
        task: str,
        models: Union[str, List[str]],
        text: str,
        device: Optional[str] = None,
        threshold: float = 0.5,
    ) -> DetectionResult:
        """Runs prediction on text using one or multiple models (ensemble).
        
        Averages confidences if multiple models are specified.
        """
        if isinstance(models, str):
            models = [models]

        if not models:
            raise ValueError("At least one model must be specified for inference.")

        results: List[DetectionResult] = []

        for model_name in models:
            model_instance = self.loader.get_model(task=task, name=model_name, device=device)
            res = model_instance.predict(text)
            results.append(res)

        # Single model optimization
        if len(results) == 1:
            return results[0]

        # Ensemble aggregation (average confidence scores)
        avg_score = sum(r.score for r in results) / len(results)
        is_detected = avg_score >= threshold
        primary_label = results[0].label if is_detected else "clean"

        return DetectionResult(
            detected=is_detected,
            score=avg_score,
            label=primary_label,
            metadata={
                "ensemble": True,
                "individual_results": [
                    {"model": m, "score": r.score, "detected": r.detected}
                    for m, r in zip(models, results)
                ],
            },
        )