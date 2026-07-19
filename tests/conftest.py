from __future__ import annotations

import pytest

from qarai_agent_guard.core.detectors.ModelReasoningDetector import (
    ModelReasoningDetector,
)
from qarai_agent_guard.core.guards.agent_guard import AgentGuard

TEST_PATTERNS = [
    {
        "id": "reasoning_override",
        "name": "Reasoning Override",
        "severity": "high",
        "pattern": r"ignore reasoning",
    },
    {
        "id": "hidden_thoughts",
        "name": "Reveal Thoughts",
        "severity": "critical",
        "pattern": r"show chain of thought",
    },
]


@pytest.fixture
def model_reasoning_detector():
    return ModelReasoningDetector(
        lang="en",
        patterns=TEST_PATTERNS,
    )


@pytest.fixture
def agent_guard(model_reasoning_detector):
    return AgentGuard(
        detectors=[model_reasoning_detector],
    )
