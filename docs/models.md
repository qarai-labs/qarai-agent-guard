# Model-Based Detection

A detector can use a machine learning model to detect threats.
The model mode runs the model against the value text.
The mixed mode runs regex rules and the model together.


## ModelConfig

`ModelConfig` carries all settings for a model.

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="huggingface",
    model="my-org/my-custom-model",
    task="text-classification",
    threshold=0.6,
)
```

### Parameters

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `provider` | `ModelProviderName` or `str` | Required | The model hosting provider. |
| `model` | `str` | Required | The model identifier. |
| `task` | `ModelTask` or `str` | `"text-classification"` | The task type that selects the model class. |
| `threshold` | `float` | `0.5` | Confidence threshold in `[0, 1]`. |
| `hf_access_token` | `str` | `None` | HuggingFace access token for private models. |
| `api_key` | `str` | `None` | API key for `provider="api"`. The API provider requires a non-empty value. |
| `output_formatter` | `Callable` | `None` | Converts raw model output to a result. Required for API models. |
| `model_options` | `dict` | `None` | Arguments for `AutoModel*.from_pretrained()`, or the connection options of an API provider. |
| `tokenizer_options` | `dict` | `None` | Arguments for `AutoTokenizer.from_pretrained()`. |
| `inference_options` | `dict` | `None` | Arguments for the model call at inference time, or the request payload of an API provider. |

`ModelConfig` validates only the field types.
It does not check the content of `model_options` or `inference_options`.
The API provider validates these two mappings when it loads.
See [API provider](#api-provider).

Raises `ConfigurationError` when:

- `provider` is not `"huggingface"` or `"api"`.
- `model` is empty.
- `task` is not a supported task.
- `threshold` is not a number in `[0, 1]`.
- `output_formatter` is not callable.
- `model_options`, `tokenizer_options`, or `inference_options` is not a dictionary.

### Providers

The library supports two types of providers: HuggingFace and API-based providers.

| Value | Provider |
| --- | --- |
| `"huggingface"` | HuggingFace Hub models and local paths |
| `"api"` | OpenAI-compatible `chat/completions` endpoints (e.g., OpenRouter, vLLM, Ollama) |


## Default Models

The library provides default models for two rule sets.
`resolve_default_model` returns the `ModelConfig` for a rule set.

```python
from qarai_agent_guard.core.models import resolve_default_model

config = resolve_default_model("prompt_injection")
```

### HuggingFace Provider

The following default models are provided for HuggingFace-hosted models:

| Rule set | Provider | Model | Task | Threshold |
| --- | --- | --- | --- | --- |
| `prompt_injection` | `huggingface` | `deepset/deberta-v3-base-injection` | `text-classification` | `0.5` |
| `pii` | `huggingface` | `SoelMgd/bert-pii-detection` | `token-classification` | `0.4` |

The PII default config also sets the inference option `aggregation_strategy` to `"simple"`.

### API-Based Providers

The following default model is provided for API-based providers (OpenRouter, vLLM, Ollama, etc.):

| Rule set | Provider | Model | Task | Threshold |
| --- | --- | --- | --- | --- |
| `prompt_injection` | `api` | `gpt-oss-120b` | `text-generation` | `0.5` |

There is no API-based default model for the PII rule set.

The API default values in full:

| Field | Value |
| --- | --- |
| `provider` | `"api"` |
| `model` | `"gpt-oss-120b"` |
| `task` | `"text-generation"` |
| `threshold` | `0.5` |
| `api_key` | `None`. You must set it. |
| `model_options["endpoint"]` | `"https://openrouter.ai/api/v1"` |
| `model_options["messages"]` | One `system` message with the classifier instructions. |
| `inference_options` | `{"temperature": 0.0, "max_tokens": 256}` |
| `output_formatter` | `_format_default_api` |

The default `inference_options` are `{"temperature": 0.0, "max_tokens": 256}`.
`gpt-oss-120b` is a reasoning model and spends part of the budget on internal reasoning, so a small `max_tokens` can leave the answer empty and raise `ModelOutputError`.
Raise `max_tokens` when you change the model or shorten the system prompt.

The system prompt asks the model for exactly one word, `safe` or `unsafe`. The matching formatter is strict: any other answer raises `ModelOutputError` instead of guessing a verdict.

### Resolving Default Models

Pass `provider` to select a provider-specific default:

```python
config = resolve_default_model("prompt_injection", provider="api")
```

The `provider` parameter accepts a `ModelProviderName` member or its string value. The table of all default combinations:

| Rule set | `provider` | Result |
| --- | --- | --- |
| `prompt_injection` | `None` | The `huggingface` default. |
| `prompt_injection` | `"huggingface"` | `deepset/deberta-v3-base-injection`. |
| `prompt_injection` | `"api"` | `gpt-oss-120b` on `https://openrouter.ai/api/v1`. |
| `pii` | `None` | The `huggingface` default. |
| `pii` | `"huggingface"` | `SoelMgd/bert-pii-detection`. |
| `pii` | `"api"` | `None`. There is no API default for PII. |
| `secrets` | Any value | `None`. There is no model default for secrets. |
| Any other value | Any value | `None`. The rule set is unknown. |

An invalid `provider` value returns `None` instead of raising an exception. The `Detector` constructor validates `provider` and raises `ConfigurationError` for an unknown value.

`resolve_default_model` returns `None` for rule sets without a default model:

```python
print(resolve_default_model("secrets"))  # None
```

It also returns `None` for an invalid rule set. It does not raise an exception. The detector layer performs configuration validation.

### Using Default Models

A detector resolves the default model automatically when you set `default_rules`:

```python
from qarai_agent_guard import Detector

detector = Detector(
    name="model_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
)
```

The default prompt-injection model is `deepset/deberta-v3-base-injection` (HuggingFace). The default PII model is `SoelMgd/bert-pii-detection` (HuggingFace).

A detector that asks for `provider="api"` without a key resolves the API default. The error then comes from the provider at the first inspection. See [API-Based Providers](#api-based-providers).

An explicit `model` takes precedence over a default model:

```python
config = ModelConfig(
    provider="huggingface",
    model="my-org/my-custom-model",
    task="text-classification",
    threshold=0.6,
)

detector = Detector(
    name="custom_model",
    detector_type="model",
    model=config,
)
```

## HuggingFace Provider

The `provider="huggingface"` setting loads and runs models from the HuggingFace Hub or local paths.
The library downloads the model and tokenizer on first use (or loads from cache). It uses the `transformers` pipeline API to run inference.

Use the HuggingFace provider when:

- You can download models locally or have access to HuggingFace Hub.
- You want to run models on your own infrastructure.
- You need token-level classification (for PII detection) or efficient local inference.

### Model Tasks

The HuggingFace provider supports four task types:

| Value | Model class | Use |
| --- | --- | --- |
| `"text-classification"` | `AutoModelForSequenceClassification` | Whole-text classification, for example prompt-injection detection. |
| `"token-classification"` | `AutoModelForTokenClassification` | Token-level labeling, for example PII or NER. |
| `"text-generation"` | `AutoModelForCausalLM` | Causal language modeling. |
| `"text2text-generation"` | `AutoModelForSeq2SeqLM` | Encoder-decoder generation. |

### Option Bags

The HuggingFace provider uses three option bags to configure model loading and inference. These are passed to the underlying transformers pipeline.

| Bag | Role | Validated |
| --- | --- | --- |
| `model_options` | Arguments for `AutoModel*.from_pretrained()`. | When loaded |
| `tokenizer_options` | Arguments for `AutoTokenizer.from_pretrained()`. | When loaded |
| `inference_options` | Arguments for the model call at inference time (pipeline arguments). | When loaded |

All three bags must be dictionaries if provided. They are validated when the provider loads. They can be used to configure device placement, torch dtype, model-specific options, and inference parameters such as `max_length`, `truncation`, and `padding`.

### Access Token and Private Models

For private models hosted on HuggingFace Hub, you can provide an access token using `hf_access_token` in `ModelConfig`:

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="huggingface",
    model="my-org/private-model",
    task="text-classification",
    threshold=0.5,
    hf_access_token="hf_...",
)
```

### Example

Example of a HuggingFace text-classification model configuration:

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="huggingface",
    model="deepset/deberta-v3-base-injection",
    task="text-classification",
    threshold=0.5,
    model_options={"torch_dtype": "float32"},
    inference_options={"truncation": True, "max_length": 512},
)
```

### PII Detection

For token-level tasks such as PII detection, use `task="token-classification"`. The PII default model is `SoelMgd/bert-pii-detection` and uses `aggregation_strategy="simple"` in inference options for optimal results.

## API-Based Providers

The `provider="api"` setting sends the inspected value to a remote endpoint.
The library does not download a model.
The library sends one HTTP request for each inspected value.

Use API-based providers when:

- You cannot download a model.
- You want a model that is stronger than a small local classifier.
- You already run an OpenAI-compatible gateway.

The endpoint must support the `chat/completions` path of the OpenAI API format.
OpenRouter, Together AI, Groq, vLLM, Ollama, and LM Studio all serve such a path.

The provider adds `/chat/completions` to the configured base URL.
Configure the base URL only.

### Configuration

Build the configuration from the library default and add the key:

```python
import os
from dataclasses import replace

from qarai_agent_guard import Detector
from qarai_agent_guard.core.models import resolve_default_model

config = replace(
    resolve_default_model("prompt_injection", provider="api"),
    api_key=os.environ["OPENROUTER_API_KEY"],
)

detector = Detector(
    name="api_prompt_injection",
    detector_type="model",
    model=config,
)
```

Read the key from the environment or from a secret manager.
Do not write the key in the source code.

`provider="api"` alone is not enough.
The default API configuration has no `api_key`.
The provider raises an error on the first inspection:

```python
detector = Detector(
    name="api_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
    provider="api",
)
# First inspect() raises:
# ModelLoadError: Failed to load model 'gpt-oss-120b' using provider 'api'
```

The `Detector` constructor has no `api_key` parameter.
Use `dataclasses.replace` to add the key to the resolved default.

### Option Bags

The API provider uses two option bags.
Each bag has its own role:

| Bag | Role | Validated |
| --- | --- | --- |
| `model_options` | Connection setup: URL, chat history, headers, timeout. | On load |
| `inference_options` | Request payload: sampling options and answer format. | On load |

Both bags reject unknown keys.
An unknown key raises `ConfigurationError` and the message lists the allowed keys.

Validation runs when the provider loads.
The first inspection loads the provider.
The `Detector` constructor does not validate these bags.

### Model Options

| Key | Type | Required | Default | Role |
| --- | --- | --- | --- | --- |
| `endpoint` | `str` | Yes | None | Base URL of the API. The library appends `/chat/completions`. |
| `messages` | `list[dict]` | Yes | None | Chat messages that the library sends before the inspected value. |
| `headers` | `dict[str, str]` | No | `{}` | Extra HTTP headers, for example an attribution header. |
| `timeout` | `float` | No | `60.0` | Timeout of the HTTP client in seconds. |

No other key is allowed in `model_options`.
There is no default for `endpoint` and no default for `messages`.

#### endpoint

Rules for `endpoint`:

- The value must be a non-empty string.
- The value must be an absolute `http` or `https` URL with a host.
- The library removes trailing `/` characters.
- The library appends `/chat/completions`.
- The value must not already end with `/chat/completions`.

| Configured value | Result |
| --- | --- |
| `"https://openrouter.ai/api/v1"` | Accepted. The request goes to `https://openrouter.ai/api/v1/chat/completions`. |
| `"https://openrouter.ai/api/v1/"` | Accepted. The trailing slash is removed. |
| `"http://localhost:11434/v1"` | Accepted. Useful for a local gateway. |
| `"https://openrouter.ai/api/v1/chat/completions"` | Rejected. Remove the `/chat/completions` suffix. |
| `"openrouter.ai/api/v1"` | Rejected. The URL has no scheme. |
| `"ftp://openrouter.ai/api/v1"` | Rejected. Only `http` and `https` are supported. |
| `""` | Rejected. The value is empty. |

#### messages

Rules for `messages`:

- The value must be a non-empty list.
- Each item must be a dict with the keys `role` and `content`.
- `role` must be `system`, `user`, or `assistant`.
- `content` must be a string.
- Other keys inside a message raise `ConfigurationError`.
- The library keeps the order of the messages.

The library appends the inspected value as one final `user` message.
The library never places the inspected value in a `system` message.

The number of configured messages has no limit.
Short histories give lower cost and lower latency.

Example:

```python
messages = [
    {"role": "system", "content": "Answer with one word: safe or unsafe."},
]
```

The library sends this body:

```json
{
  "model": "gpt-oss-120b",
  "messages": [
    {"role": "system", "content": "Answer with one word: safe or unsafe."},
    {"role": "user", "content": "<the inspected value>"}
  ]
}
```

#### headers

Rules for `headers`:

- Each name must be a non-empty string.
- Each value must be a string.

The library merges `headers` after `Authorization` and `Content-Type`.
A header in `headers` can therefore replace one of these two headers.

Do not put the API key in `headers`.
The library already sends the key in the `Authorization` header.

#### timeout

Rules for `timeout`:

- The value must be a number, an `int` or a `float`.
- A boolean is not a number here. It raises `ConfigurationError`.
- The value must be finite and greater than `0`.
- The default is `60.0` seconds.

The library never replaces an invalid value with the default.
An invalid value raises `ConfigurationError`.

The timeout covers the whole request.
It also covers the wait for the first answer byte.

### Inference Options

| Key | Type | Allowed range | Sent when omitted | Role |
| --- | --- | --- | --- | --- |
| `temperature` | number | `0.0` to `2.0` | Not sent | Sampling randomness. `0.0` gives the most stable answer. |
| `max_tokens` | integer | Greater than `0` | Not sent | Maximum answer length in tokens. |
| `top_p` | number | `0.0` to `1.0` | Not sent | Nucleus sampling. |
| `frequency_penalty` | number | `-2.0` to `2.0` | Not sent | Reduces repeated tokens. |
| `presence_penalty` | number | `-2.0` to `2.0` | Not sent | Reduces repeated topics. |
| `response_format` | `str` or `dict` | Not empty | Not sent | Requests a structured answer, for example `{"type": "json_object"}`. |

Rules for all keys:

- The library sends no inference option when you configure none.
- The endpoint then uses its own defaults.
- A boolean is not a number here. It raises `ConfigurationError`.
- `NaN` and infinity raise `ConfigurationError`.
- `max_tokens` must be an `int`. A float such as `256.0` raises `ConfigurationError`.

### Examples

#### OpenRouter

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="gpt-oss-120b",
    task="text-generation",
    threshold=0.5,
    api_key="<your-openrouter-key>",
    output_formatter=my_formatter,   # See "Verdict formatter" below.
    model_options={
        "endpoint": "https://openrouter.ai/api/v1",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security classifier. "
                    "Answer with exactly one word: safe or unsafe."
                ),
            }
        ],
        "headers": {"X-Title": "my-app"},
        "timeout": 30.0,
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)
```

#### vLLM

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="meta-llama/Meta-Llama-3-8B-Instruct",
    task="text-generation",
    threshold=0.5,
    api_key="",  # Set empty if no authentication is required
    model_options={
        "endpoint": "http://localhost:8000/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
        "timeout": 30.0,
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)
```

#### Ollama

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="llama3.2",
    task="text-generation",
    threshold=0.5,
    api_key="",  # Ollama does not require an API key
    model_options={
        "endpoint": "http://localhost:11434/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
        "timeout": 30.0,
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)
```

### Request

The provider sends one `POST` request per value.

| Part | Value |
| --- | --- |
| Method | `POST` |
| URL | `<endpoint>/chat/completions` |
| `Authorization` | `Bearer <api_key>` |
| `Content-Type` | `application/json` |
| Body | JSON object |

Body fields:

| Field | Source |
| --- | --- |
| `model` | `ModelConfig.model` |
| `messages` | `model_options["messages"]` plus the inspected value |
| `temperature`, `max_tokens`, `top_p`, `frequency_penalty`, `presence_penalty`, `response_format` | `inference_options` |

The library sends no other body field.
It does not send `n`, `stream`, `tools`, or `seed`.

### Response

The provider returns the value of `choices[0].message.content`.
It returns this value without any change.
The `InferenceEngine` then calls the output formatter.

The provider reads the first choice only.
A response with an empty `choices` list raises `ModelOutputError`.

### Failures

The provider maps every failure to one exception type:

| Situation | Exception | Message |
| --- | --- | --- |
| `api_key` is empty or missing | `ConfigurationError` on load | `api_key is required for API provider` |
| `model_options` or `inference_options` is invalid | `ConfigurationError` on load | Lists the rejected value. |
| Status `429` | `ModelRateLimitError` | `API rate limit reached (429) for <endpoint>, retry after <value>: <body>` |
| Any other status `4xx` or `5xx` | `ModelInferenceError` | `API request failed with status <code>: <body>` |
| Network error, refused connection, or timeout | `ModelInferenceError` | `API request to <endpoint> failed: <error>` |
| The body is not valid JSON | `ModelOutputError` | `API response is not valid JSON: <error>` |
| The body is not a JSON object | `ModelOutputError` | `API response must be a JSON object` |
| `choices` is missing or empty | `ModelOutputError` | `API response is missing a non-empty 'choices' list` |
| `choices[0]` is not a JSON object | `ModelOutputError` | `API response 'choices[0]' must be a JSON object` |
| `message` is missing | `ModelOutputError` | `API response is missing 'choices[0].message'` |
| `content` is `null` | `ModelOutputError` | `API response is missing 'choices[0].message.content'` |
| `predict` runs before `load` | `ModelInferenceError` | `provider has not been loaded` |
| The verdict text is not `safe` or `unsafe` | `ModelOutputError` | Comes from the output formatter. |

`ModelRateLimitError` extends `ModelInferenceError`.
One `except ModelInferenceError` clause catches both.

The `Retry-After` header of a `429` response becomes part of the message.
The body of a failed response is shortened to 500 characters.
Long bodies end with `...`.

The `ModelLoader` wraps every load failure in `ModelLoadError`.
The original `ConfigurationError` stays available as the cause:

```python
try:
    detector.inspect(key="mem", value="hello", operation="write")
except ModelLoadError as exc:
    print(exc.__cause__)
    # api_key is required for API provider
```

#### Truncated answers

A reasoning model can spend the whole token budget on internal reasoning.
The endpoint then returns `finish_reason` with the value `length` and no answer.

The provider adds a hint to the error message:

```text
API response is missing 'choices[0].message.content' (finish_reason='length': raise 'max_tokens' so the model can finish its answer)
```

Raise `max_tokens` when you see this message.
The library default for the API configuration is `256`.

### Verdict formatter

The default API configuration uses `_format_default_api` as `output_formatter`.
The formatter reads the assistant message text.

| Answer | Result |
| --- | --- |
| `unsafe` | `detected=True`, `score=1.0`, `severity=Severity.CRITICAL` |
| `safe` | `detected=False`, `score=0.0`, `severity=Severity.LOW` |

The formatter ignores case and surrounding whitespace.
`Safe`, `SAFE`, and ` safe ` all mean `safe`.

Any other answer raises `ModelOutputError`.
The formatter never guesses a verdict.

The metadata of the result contains the verdict:

```python
{"verdict": "unsafe"}
```

The formatter does not use `threshold`.
The verdict text decides the result.

An API model always needs an `output_formatter`.
Without one, the generic `DefaultOutputFormatter` receives a plain string
and raises `ModelOutputError` with `Unsupported model output`.

Write a custom formatter when the endpoint answers in another format:

```python
import json

from qarai_agent_guard.core.schemas import Severity
from qarai_agent_guard.core.schemas.models import ModelDetectionResult


def json_verdict_formatter(raw, config):
    data = json.loads(raw)
    label = str(data["label"]).lower()
    score = float(data["score"])
    detected = label in {"unsafe", "injection"}

    return ModelDetectionResult(
        detected=detected,
        score=score,
        severity=Severity.CRITICAL if detected else Severity.LOW,
        metadata={"label": label},
    )
```

Set `response_format` to `{"type": "json_object"}` so the endpoint answers with JSON.

### Default behaviour

The table lists what the library does when you configure nothing:

| Item | Default behaviour |
| --- | --- |
| `api_key` | None. An empty or missing key raises `ConfigurationError`. |
| `endpoint` suffix | The library appends `/chat/completions`. |
| Authentication | The library sends `Authorization: Bearer <api_key>`. |
| Content type | The library sends `Content-Type: application/json`. |
| Inspected value | The library appends it as the last `user` message. |
| `headers` | Empty. No extra header is sent. |
| `timeout` | `60.0` seconds. |
| `inference_options` | None. No sampling option is sent. |
| Retries | None. The library sends every request once. |
| Streaming | Off. |
| Number of choices | Not sent. Only the first choice is read. |
| Key in logs | The library never logs the key. |
| Answer cache | None. Each inspection sends one request. |

### Provider caching

The `ModelLoader` caches one loaded provider per configuration.
The cache key covers `provider`, `model`, `task`, `model_options`,
and `tokenizer_options`.

The cache key does not cover `api_key` or `inference_options`.
Two consequences follow:

- Two configurations with the same endpoint, messages, and model share one
  provider. The key of the first load is the key of the shared provider.
- A change to `inference_options` alone has no effect on a cached provider.
  The provider reads these options when it loads.

Change `endpoint`, `messages`, or `model` to force a new provider.
Or clear the loader:

```python
from qarai_agent_guard.core.models import ModelLoader

loader = ModelLoader()
loader.clear()
```

### Latency, cost, and rate limits

- One inspected value causes one HTTP request.
- The library does not batch values.
- The library does not cache answers.
- Every request is billable at the endpoint.
- An empty value sends no request. The detector returns `matched=False`.
- `execution_strategy="fail_fast"` can remove the request when a regex detector
  matched first.

The endpoint sets the rate limits.
The library reports a limit as `ModelRateLimitError`.
See [Security Modes & Runtime Behaviour](runtime.md) for the guard reaction.

### Security Notes

- The inspected value leaves your system. Send only data that the endpoint may read.
- Use `https` for every remote endpoint.
- Keep the key in an environment variable or in a secret manager.
- The library never logs the key. Error messages contain the endpoint and the
  response body only.
- Do not put the key in `headers`. Send no key to an `http` endpoint.
- Use regex detectors only when the value must not leave your system.

### Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `api_key is required for API provider` | The configuration has no key. | Add the key with `dataclasses.replace`. |
| `model_options is missing required key(s): endpoint, messages` | The bag is incomplete. | Add both keys. |
| `unknown model_options key(s): ...` | A key is misspelled or belongs to a HuggingFace model. | Use only `endpoint`, `messages`, `headers`, `timeout`. |
| `endpoint must be the base URL without the '/chat/completions' suffix` | The full URL was configured. | Remove the suffix. |
| `unknown inference_options key(s): ...` | A key is not supported. | Use only the six documented keys. |
| `finish_reason='length'` in the message | `max_tokens` is too small for a reasoning model. | Raise `max_tokens`. |
| `must answer exactly 'safe' or 'unsafe'` | The model returned other text. | Strengthen the system prompt or write a lenient formatter. |
| `API rate limit reached (429)` | The endpoint throttles the requests. | Wait for `Retry-After` and lower the request rate. |
| `API request failed with status 401` | The key is wrong or expired. | Check the key. |
| `API request failed with status 404` | The base URL is wrong. | Check `endpoint`. |
| `Detector '<name>' failed: ...` in the decision reason | The guard uses `fail_closed` and the API call failed. | See [Security Modes & Runtime Behaviour](runtime.md). |
| A changed `inference_options` value has no effect | The provider is cached. | Change the `messages`, call `loader.clear()`, or use a new process. |

## Output Formatting

The model provider returns raw model output.
The inference engine converts the raw output into a `ModelDetectionResult`.

### DefaultOutputFormatter

`DefaultOutputFormatter` recognizes these output shapes:

| Shape | Detection rule |
| --- | --- |
| `bool` | `True` is a detection. |
| Integer `0` or `1` | `1` is a detection. |
| Float in `[0, 1]` | A detection when the score meets `threshold`. |
| `{"label": str, "score": float}` | A detection when the score meets `threshold`. |
| `list` of token entities | A detection when any entity score meets `threshold`. |
| `[{"generated_text": str}]` | A detection when the text matches a positive verdict word. |

Positive verdict words: `true`, `yes`, `unsafe`, `block`, `malicious`, `injection`.
Negative verdict words: `false`, `no`, `safe`, `allow`, `benign`, `clean`.

`DefaultOutputFormatter` raises `ModelOutputError` for unsupported output.

Models with custom heads, JSON text output, or custom label semantics need an explicit `output_formatter`.

`DefaultOutputFormatter` does not read a plain string.
It supports booleans, numbers, dicts, and lists only.
An API model returns the message content as a string.
An API model therefore always needs an explicit `output_formatter`.
See [Verdict formatter](#verdict-formatter).

### ModelDetectionResult

A formatter returns a `ModelDetectionResult`:

| Field | Type | Role |
| --- | --- | --- |
| `detected` | `bool` | Whether the model found a threat. |
| `score` | `float` or `None` | The detection score. |
| `severity` | `Severity` or `None` | The detection severity. |
| `metadata` | `dict` | Extra context. |
| `entities` | `list[dict]` | Detected entities for redaction. |

When `detected` is `True` and no severity is given, the severity becomes `CRITICAL`.
When `detected` is `False` and no severity is given, the severity becomes `LOW`.

### External model with an explicit formatter

The provider may return output that the default formatter cannot read.
In this case, write an explicit `output_formatter`.

The formatter signature is:

```python
def formatter(raw_output, config) -> ModelDetectionResult:
    ...
```

It receives the raw provider output and the `ModelConfig`.
It must return a `ModelDetectionResult`.
The `InferenceEngine` raises `ModelFormatterError` when the formatter returns another type.

Example for a text-classification model:

```python
from qarai_agent_guard.core.models import ModelConfig
from qarai_agent_guard.core.schemas import Severity
from qarai_agent_guard.core.schemas.models import ModelDetectionResult


def classify_formatter(raw, config):
    item = raw[0] if isinstance(raw, list) else raw
    label = str(item["label"]).upper()
    score = float(item["score"])
    detected = label in {"INJECTION", "LABEL_1", "PROMPT_INJECTION"} and score >= config.threshold
    return ModelDetectionResult(
        detected=detected,
        score=score if detected else 1 - score,
        severity=Severity.CRITICAL if detected else Severity.LOW,
        metadata={"raw_label": item["label"], "raw_score": score},
    )


config = ModelConfig(
    provider="huggingface",
    model="deepset/deberta-v3-base-injection",
    task="text-classification",
    threshold=0.5,
    output_formatter=classify_formatter,
)

detector = Detector(
    name="external_model",
    detector_type="model",
    model=config,
)
```

Example for a token-classification model:

```python
def token_formatter(raw, config):
    entities = [
        item
        for item in raw
        if item.get("entity_group", item.get("entity", "O")) not in ("O", "")
        and float(item.get("score", 0)) >= config.threshold
    ]
    score = max((float(item["score"]) for item in entities), default=0.0)
    return ModelDetectionResult(
        detected=bool(entities),
        score=score,
        severity=Severity.CRITICAL if entities else Severity.LOW,
        entities=entities,
        metadata={"detected_token_count": len(entities)},
    )
```

## Inference Engine

`InferenceEngine` executes model inference and normalizes the output.

The detector creates an engine automatically.
You can share one engine across detectors:

```python
from qarai_agent_guard.core.models import InferenceEngine, ModelLoader
from qarai_agent_guard import Detector

loader = ModelLoader()
engine = InferenceEngine(loader)

first = Detector(
    name="injection_a",
    detector_type="model",
    default_rules="prompt_injection",
    inference_engine=engine,
)

second = Detector(
    name="injection_b",
    detector_type="model",
    default_rules="prompt_injection",
    inference_engine=engine,
)
```

`InferenceEngine.predict` runs this process:

1. Load the provider through the `ModelLoader`.
2. Call the provider with the value text.
3. Format the raw output with the configured formatter.
4. Return the `ModelDetectionResult`.

## Model Loader

`ModelLoader` loads, caches, and unloads model providers.

The loader caches providers by model configuration.
Multiple detectors that use the same model share one loaded pipeline.

The cache key covers the provider, the model identifier, the task, and the model and tokenizer options.
It does not cover the threshold, the output formatter, the API key, or the inference options.

```python
loader = ModelLoader()
provider = loader.get(config)   # Loads and caches the model
loader.release(config)          # Unloads one provider
loader.clear()                  # Unloads all providers
```

Methods:

| Method | Role |
| --- | --- |
| `get(config)` | Returns a loaded provider for the configuration. Loads the model on first access. |
| `release(config)` | Removes and unloads the provider. |
| `clear()` | Removes and unloads all cached providers. |

`get` raises `ModelLoadError` when the model cannot load.
`release` raises `ModelLoadError` when the unload fails.
`clear` raises `ModelLoadError` when at least one unload fails.

`get` wraps the original failure in `ModelLoadError`.
Read `__cause__` to get the original message.
This rule also applies to invalid API options.
