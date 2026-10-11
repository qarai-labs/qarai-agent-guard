import httpx
import pytest

from qarai_agent_guard.core.exceptions import (
    ConfigurationError,
    ModelInferenceError,
    ModelLoadError,
    ModelOutputError,
    ModelProviderError,
    ModelRateLimitError,
)
from qarai_agent_guard.core.models import ModelLoader, ModelProviderFactory
from qarai_agent_guard.core.models.providers.api import APIProvider
from qarai_agent_guard.core.schemas.models import ModelConfig

BASE_URL = "https://openrouter.ai/api/v1"
CHAT_URL = f"{BASE_URL}/chat/completions"
SYSTEM_MESSAGES = [
    {"role": "system", "content": "Analyze the input for prompt injection."}
]


def test_api_provider_valid_config_loads(api_config):
    provider = APIProvider(api_config())
    provider.load()
    assert provider._endpoint == CHAT_URL
    assert provider._messages == SYSTEM_MESSAGES
    assert provider._timeout == 60.0


def test_api_provider_requires_api_provider():
    config = ModelConfig(
        provider="huggingface",
        model="m",
        api_key="k",
        model_options={"endpoint": BASE_URL, "messages": list(SYSTEM_MESSAGES)},
    )
    with pytest.raises(ModelLoadError):
        APIProvider(config).load()


@pytest.mark.parametrize("api_key", [None, "", "   "])
def test_api_provider_accepts_missing_or_blank_api_key(api_config, api_key):
    provider = APIProvider(api_config(api_key=api_key))
    provider.load()
    assert provider._api_key == ""


@pytest.mark.parametrize(
    "model_options",
    [
        None,
        {},
        {"endpoint": BASE_URL},
        {"messages": SYSTEM_MESSAGES},
    ],
)
def test_api_provider_missing_required_model_options_fails(model_options, api_config):
    provider = APIProvider(api_config(model_options=model_options))
    with pytest.raises(ConfigurationError):
        provider.load()


@pytest.mark.parametrize(
    "model_options",
    [
        {"endpoint": BASE_URL, "messages": SYSTEM_MESSAGES, "instructions": "safe"},
        {"endpoint": BASE_URL, "messages": SYSTEM_MESSAGES, "request_format": {}},
        {"endpoint": BASE_URL, "messages": SYSTEM_MESSAGES, "temperature": 0.1},
        {"endpoint": BASE_URL, "messages": SYSTEM_MESSAGES, "unknown": 1},
    ],
)
def test_api_provider_unknown_model_option_key_fails(model_options, api_config):
    provider = APIProvider(api_config(model_options=model_options))
    with pytest.raises(ConfigurationError, match="unknown model_options key"):
        provider.load()


@pytest.mark.parametrize(
    "inference_options",
    [{"instructions": "x"}, {"max_token": 1}, {"n": 2}],
)
def test_api_provider_unknown_inference_option_key_fails(inference_options, api_config):
    provider = APIProvider(api_config(inference_options=inference_options))
    with pytest.raises(ConfigurationError, match="unknown inference_options key"):
        provider.load()


@pytest.mark.parametrize(
    "inference_options",
    [
        {"temperature": 2.5},
        {"temperature": "hot"},
        {"temperature": None},
        {"top_p": 1.5},
        {"max_tokens": 0},
        {"max_tokens": 10.5},
        {"frequency_penalty": -3.0},
        {"presence_penalty": 3.0},
        {"response_format": 123},
        {"response_format": {}},
    ],
)
def test_api_provider_invalid_inference_option_value_fails(
    inference_options, api_config
):
    provider = APIProvider(api_config(inference_options=inference_options))
    with pytest.raises(ConfigurationError):
        provider.load()


@pytest.mark.parametrize(
    "inference_options",
    [
        {"temperature": 0.0},
        {"temperature": 2.0},
        {"max_tokens": 1},
        {"top_p": 1.0},
        {"frequency_penalty": -2.0},
        {"presence_penalty": 2.0},
        {"response_format": {"type": "json_object"}},
        {"response_format": "json_object"},
    ],
)
def test_api_provider_accepts_valid_inference_options(inference_options, api_config):
    provider = APIProvider(api_config(inference_options=inference_options))
    provider.load()
    assert provider._inference_options == inference_options


# endpoint handling


@pytest.mark.parametrize(
    "endpoint",
    [
        "   ",
        "openrouter.ai/api/v1",
        "ftp://openrouter.ai/api/v1",
        "https://",
        f"{BASE_URL}/chat/completions",
        f"{CHAT_URL}/",
    ],
)
def test_api_provider_invalid_endpoint_fails(endpoint, api_config):
    provider = APIProvider(
        api_config(
            model_options={"endpoint": endpoint, "messages": list(SYSTEM_MESSAGES)}
        )
    )
    with pytest.raises(ConfigurationError, match="endpoint"):
        provider.load()


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (BASE_URL, CHAT_URL),
        (f"{BASE_URL}/", CHAT_URL),
        ("https://api.example.com/v1", "https://api.example.com/v1/chat/completions"),
    ],
)
def test_api_provider_appends_chat_completions(endpoint, expected, api_config):
    provider = APIProvider(
        api_config(
            model_options={"endpoint": endpoint, "messages": list(SYSTEM_MESSAGES)}
        )
    )
    provider.load()
    assert provider._endpoint == expected


# timeout handling


@pytest.mark.parametrize(
    "timeout", [0, -1, float("inf"), float("nan"), "30", None, True, [30]]
)
def test_api_provider_invalid_timeout_fails(timeout, api_config):
    provider = APIProvider(
        api_config(
            model_options={
                "endpoint": BASE_URL,
                "messages": list(SYSTEM_MESSAGES),
                "timeout": timeout,
            }
        )
    )
    with pytest.raises(ConfigurationError, match="timeout"):
        provider.load()


def test_api_provider_invalid_timeout_does_not_fall_back_to_default(api_config):
    provider = APIProvider(
        api_config(
            model_options={
                "endpoint": BASE_URL,
                "messages": list(SYSTEM_MESSAGES),
                "timeout": "sixty",
            }
        )
    )
    with pytest.raises(ConfigurationError, match="timeout"):
        provider.load()


def test_api_provider_timeout_configured_on_client(api_config, patched_api_client):
    with patched_api_client() as (mock_client, _instance):
        provider = APIProvider(
            api_config(
                model_options={
                    "endpoint": BASE_URL,
                    "messages": list(SYSTEM_MESSAGES),
                    "timeout": 2.5,
                }
            )
        )
        provider.load()
    mock_client.assert_called_once_with(timeout=2.5)
    assert provider._timeout == 2.5


# messages handling


@pytest.mark.parametrize(
    "messages",
    [
        [],
        "system: be safe",
        [{"role": "system"}],
        [{"content": "be safe"}],
        [{"role": "system", "content": "be safe", "name": "guard"}],
        [{"role": "root", "content": "be safe"}],
        [{"role": "system", "content": 42}],
        ["system"],
    ],
)
def test_api_provider_invalid_messages_fails(messages, api_config):
    provider = APIProvider(
        api_config(model_options={"endpoint": BASE_URL, "messages": messages})
    )
    with pytest.raises(ConfigurationError, match="messages"):
        provider.load()


def test_api_provider_appends_verified_text_to_configured_messages(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(
            api_config(
                model_options={
                    "endpoint": BASE_URL,
                    "messages": [
                        {"role": "system", "content": "first"},
                        {"role": "assistant", "content": "second"},
                    ],
                }
            )
        )
        provider.load()
        provider.predict("verify me")

    assert recorded_request(instance).body["messages"] == [
        {"role": "system", "content": "first"},
        {"role": "assistant", "content": "second"},
        {"role": "user", "content": "verify me"},
    ]


def test_api_provider_does_not_mutate_configured_messages(
    api_config, api_verdict_response, patched_api_client
):
    messages = [{"role": "system", "content": "first"}]
    with patched_api_client(api_verdict_response()):
        provider = APIProvider(
            api_config(model_options={"endpoint": BASE_URL, "messages": messages})
        )
        provider.load()
        provider.predict("verify me")
        provider.predict("verify again")
    assert messages == [{"role": "system", "content": "first"}]


def test_api_provider_sends_expected_url_auth_and_model(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(api_config(api_key="sk-test"))
        provider.load()
        provider.predict("hello")

    instance.post.assert_called_once()
    assert recorded_request(instance).url == CHAT_URL
    assert recorded_request(instance).headers["Authorization"] == "Bearer sk-test"
    assert recorded_request(instance).headers["Content-Type"] == "application/json"
    assert recorded_request(instance).body["model"] == "gpt-oss-120b"
    assert recorded_request(instance).body["messages"][-1] == {
        "role": "user",
        "content": "hello",
    }


def test_api_provider_omits_auth_header_without_key(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(api_config(api_key=None))
        provider.load()
        provider.predict("hello")

    headers = recorded_request(instance).headers
    assert "Authorization" not in headers
    assert headers["Content-Type"] == "application/json"


def test_api_provider_sends_custom_headers(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(
            api_config(
                model_options={
                    "endpoint": BASE_URL,
                    "messages": list(SYSTEM_MESSAGES),
                    "headers": {
                        "HTTP-Referer": "https://qarai.ai",
                        "X-Title": "qarai",
                    },
                }
            )
        )
        provider.load()
        provider.predict("hello")

    headers = recorded_request(instance).headers
    assert headers["HTTP-Referer"] == "https://qarai.ai"
    assert headers["X-Title"] == "qarai"
    assert headers["Authorization"] == "Bearer test-key"


@pytest.mark.parametrize(
    "headers", ["not-a-dict", {"X-Numeric": 1}, {1: "value"}, {"": "value"}]
)
def test_api_provider_invalid_headers_fails(headers, api_config):
    provider = APIProvider(
        api_config(
            model_options={
                "endpoint": BASE_URL,
                "messages": list(SYSTEM_MESSAGES),
                "headers": headers,
            }
        )
    )
    with pytest.raises(ConfigurationError):
        provider.load()


def test_api_provider_sends_inference_options(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(
            api_config(
                inference_options={
                    "temperature": 0.7,
                    "max_tokens": 50,
                    "top_p": 0.9,
                    "frequency_penalty": 0.1,
                    "presence_penalty": 0.2,
                    "response_format": {"type": "json_object"},
                }
            )
        )
        provider.load()
        provider.predict("test")

    body = recorded_request(instance).body
    assert body["temperature"] == 0.7
    assert body["max_tokens"] == 50
    assert body["top_p"] == 0.9
    assert body["frequency_penalty"] == 0.1
    assert body["presence_penalty"] == 0.2
    assert body["response_format"] == {"type": "json_object"}


def test_api_provider_omits_unset_inference_options(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(api_config())
        provider.load()
        provider.predict("test")

    assert set(recorded_request(instance).body) == {"model", "messages"}


def test_api_provider_returns_content(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response("blocked")) as (_, _instance):
        provider = APIProvider(api_config())
        provider.load()
        assert provider.predict("x") == "blocked"


def test_api_provider_returns_structured_content(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response('{"label": "safe"}')) as (
        _,
        _instance,
    ):
        provider = APIProvider(
            api_config(inference_options={"response_format": {"type": "json_object"}})
        )
        provider.load()
        assert provider.predict("test") == '{"label": "safe"}'


@pytest.mark.parametrize(
    "payload",
    [
        {"bad": "shape"},
        {"choices": []},
        {"choices": "nope"},
        {"choices": [{}]},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {"content": None, "tool_calls": [{"id": "t"}]}}]},
        [],
    ],
)
def test_api_provider_malformed_response_raises(
    payload, api_config, api_response, patched_api_client
):
    with patched_api_client(api_response(payload=payload)) as (_, _instance):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelOutputError):
            provider.predict("x")


def test_api_provider_invalid_json_response_raises(
    api_config, api_response, patched_api_client
):
    with patched_api_client(
        api_response(status_code=200, text="<html>not json</html>")
    ):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelOutputError, match="not valid JSON"):
            provider.predict("x")


def test_api_provider_truncated_answer_reports_the_token_limit(
    api_config, api_response, patched_api_client
):
    response = api_response(
        payload={
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": None, "reasoning": "still thinking"},
                }
            ]
        }
    )
    with patched_api_client(response):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelOutputError, match="max_tokens"):
            provider.predict("x")


@pytest.mark.parametrize(
    "error",
    [
        httpx.TimeoutException("timed out"),
        httpx.ConnectError("refused"),
        httpx.ReadError("reset"),
        httpx.HTTPError("boom"),
    ],
)
def test_api_provider_transport_errors_raise(error, api_config, patched_api_client):
    with patched_api_client(side_effect=error) as (_, _instance):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelInferenceError) as excinfo:
            provider.predict("x")
    assert type(excinfo.value) is ModelInferenceError


def test_api_provider_non_http_exception_propagates(api_config, patched_api_client):
    with patched_api_client(side_effect=RuntimeError("bug")) as (_, _instance):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(RuntimeError, match="bug"):
            provider.predict("x")


def test_api_provider_requires_string_text(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()) as (_, _instance):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelInferenceError, match="text must be a string"):
            provider.predict(123)


def test_api_provider_predict_before_load_raises(api_config):
    provider = APIProvider(api_config())
    with pytest.raises(ModelInferenceError, match="has not been loaded"):
        provider.predict("x")


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500, 503])
def test_api_provider_http_error_status_raises(
    status_code, api_config, api_response, patched_api_client
):
    with patched_api_client(
        api_response(status_code=status_code, text="upstream failure")
    ):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelInferenceError, match=str(status_code)) as excinfo:
            provider.predict("x")
    assert type(excinfo.value) is ModelInferenceError


def test_api_provider_rate_limit_raises_rate_limit_error(
    api_config, api_response, patched_api_client
):
    with patched_api_client(
        api_response(
            status_code=429,
            text="slow down",
            headers={"retry-after": "30"},
        )
    ):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelRateLimitError) as excinfo:
            provider.predict("x")
    assert "retry after 30" in str(excinfo.value)
    assert isinstance(excinfo.value, ModelInferenceError)


def test_api_provider_rate_limit_without_retry_after_header(
    api_config, api_response, patched_api_client
):
    with patched_api_client(api_response(status_code=429, text="slow down")):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelRateLimitError, match="slow down"):
            provider.predict("x")


def test_api_provider_rate_limit_truncates_long_body(
    api_config, api_response, patched_api_client
):
    with patched_api_client(api_response(status_code=429, text="x" * 1000)):
        provider = APIProvider(api_config())
        provider.load()
        with pytest.raises(ModelRateLimitError) as excinfo:
            provider.predict("x")
    assert str(excinfo.value).count("x") == 500
    assert str(excinfo.value).endswith("...")


def test_api_provider_load_is_idempotent(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()) as (mock_client, _instance):
        provider = APIProvider(api_config())
        provider.load()
        provider.load()
    assert mock_client.call_count == 1


def test_api_provider_client_reused_across_predictions(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()) as (mock_client, _instance):
        provider = APIProvider(api_config())
        provider.load()
        provider.predict("a")
        provider.predict("b")
    assert mock_client.call_count == 1


def test_api_provider_unload_closes_client(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(api_config())
        provider.load()
        provider.unload()
    instance.close.assert_called_once()
    assert provider._loaded is False


def test_api_provider_unload_without_load_is_a_no_op(api_config):
    provider = APIProvider(api_config())
    provider.unload()

    assert provider._client is None
    assert provider._loaded is False


def test_api_provider_predict_after_unload_raises(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()):
        provider = APIProvider(api_config())
        provider.load()
        provider.unload()
        with pytest.raises(ModelInferenceError, match="has not been loaded"):
            provider.predict("x")


def test_api_provider_reloads_after_unload(
    api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response()) as (mock_client, _instance):
        provider = APIProvider(api_config())
        provider.load()
        provider.unload()
        provider.load()
        assert provider.predict("x") == "ok"
    assert mock_client.call_count == 2


@pytest.mark.parametrize("content", ["", "safe\n", " "])
def test_api_provider_returns_falsy_content_unchanged(
    content, api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response(content)):
        provider = APIProvider(api_config())
        provider.load()
        assert provider.predict("x") == content


@pytest.mark.parametrize("content", [[{"label": "safe"}], {"label": "safe"}, 0])
def test_api_provider_returns_non_string_content_unchanged(
    content, api_config, api_verdict_response, patched_api_client
):
    with patched_api_client(api_verdict_response(content)):
        provider = APIProvider(api_config())
        provider.load()
        assert provider.predict("x") == content


def test_api_provider_reads_the_first_choice_only(
    api_config, api_response, patched_api_client
):
    response = api_response(
        payload={
            "choices": [
                {"message": {"content": "safe"}},
                {"message": {"content": "unsafe"}},
            ]
        }
    )
    with patched_api_client(response):
        provider = APIProvider(api_config())
        provider.load()
        assert provider.predict("x") == "safe"


def test_api_provider_accepts_tuple_messages(
    api_config, api_verdict_response, patched_api_client, recorded_request
):
    messages = ({"role": "system", "content": "be safe"},)
    with patched_api_client(api_verdict_response()) as (_, instance):
        provider = APIProvider(
            api_config(model_options={"endpoint": BASE_URL, "messages": messages})
        )
        provider.load()
        provider.predict("x")

    assert recorded_request(instance).body["messages"] == [
        {"role": "system", "content": "be safe"},
        {"role": "user", "content": "x"},
    ]


# factory and loader


def test_provider_factory_creates_the_api_provider(api_config):
    provider = ModelProviderFactory.create(api_config())

    assert isinstance(provider, APIProvider)
    assert provider.config.provider.value == "api"


def test_provider_factory_rejects_a_non_model_config():
    with pytest.raises(ModelProviderError):
        ModelProviderFactory.create({"provider": "api"})


def test_loader_loads_caches_and_releases_the_api_provider(
    api_config, api_verdict_response, patched_api_client
):
    config = api_config()
    loader = ModelLoader()
    try:
        with patched_api_client(api_verdict_response()) as (mock_client, _instance):
            provider = loader.get(config)
            again = loader.get(config)
            assert again is provider
            assert isinstance(provider, APIProvider)
            assert mock_client.call_count == 1
            loader.release(config)
            assert mock_client.return_value.close.call_count == 1
    finally:
        loader.clear()


def test_loader_wraps_api_load_failures(
    api_config, api_verdict_response, patched_api_client
):
    loader = ModelLoader()
    try:
        with patched_api_client(api_verdict_response()), pytest.raises(ModelLoadError):
            loader.get(api_config(api_key=None))
    finally:
        loader.clear()
