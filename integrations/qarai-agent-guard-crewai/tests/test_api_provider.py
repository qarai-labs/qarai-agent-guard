from __future__ import annotations

import pytest
from qarai_agent_guard import AgentGuardViolation

from qarai_agent_guard_crewai.global_hooks import enable_guard

from .conftest import (
    CUSTOM_SYSTEM_PROMPT,
    OPENROUTER_ENDPOINT,
    PROMPT_INJECTION_TEXT,
    fire_before_llm,
    make_llm_context,
    openrouter_guard,
    openrouter_model,
    openrouter_request_body,
)


def test_default_openrouter_model_blocks_injection_through_before_llm(
    openrouter_transport,
):
    """The default API prompt uses OpenRouter and blocks an unsafe verdict."""
    enable_guard(openrouter_guard(openrouter_model()))

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(
            make_llm_context(
                messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
            )
        )

    assert len(openrouter_transport) == 1
    request = openrouter_transport[0]
    assert str(request.url) == f"{OPENROUTER_ENDPOINT}/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-openrouter-key"
    body = openrouter_request_body(request)
    assert body["model"] == "gpt-oss-120b"
    assert "You are a security classifier" in body["messages"][0]["content"]
    assert body["messages"][-1]["content"] == PROMPT_INJECTION_TEXT


def test_explicit_openrouter_messages_and_prompt_block_injection(
    openrouter_transport,
):
    """A custom API model sends its configured messages and prompt."""
    enable_guard(openrouter_guard(openrouter_model(explicit=True)))

    with pytest.raises(AgentGuardViolation):
        fire_before_llm(
            make_llm_context(
                messages=[{"role": "user", "content": PROMPT_INJECTION_TEXT}]
            )
        )

    assert len(openrouter_transport) == 1
    request = openrouter_transport[0]
    assert str(request.url) == f"{OPENROUTER_ENDPOINT}/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-openrouter-key"
    body = openrouter_request_body(request)
    assert body["model"] == "openai/gpt-4o-mini"
    assert body["messages"][0] == {
        "role": "system",
        "content": CUSTOM_SYSTEM_PROMPT,
    }
    assert body["messages"][-1]["content"] == PROMPT_INJECTION_TEXT
