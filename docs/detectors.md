# Detectors

A `Detector` inspects an arbitrary value for a class of security threat.
The user sends a value, a key, and an operation name to the detector.
The detector returns a `DetectionResult`.


## Construction

Create a detector with the `Detector` constructor:

```python
from qarai_agent_guard import Detector

detector = Detector(name="pii", default_rules="pii")
```

All parameters are keyword-only.

The detector default name is `"detector"`:

```python
detector = Detector(default_rules="pii")
print(detector.name)  # detector
```

Give every detector a unique name when you use several detectors in one guard.

## Parameters

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `lang` | `str` | `"en"` | Language for language-dependent default rules. |
| `name` | `str` | `"detector"` | Unique detector name. |
| `patterns` | `list[dict]` | `None` | Inline regex rule definitions. |
| `pattern_paths` | `list[Path]` | `None` | Paths to YAML rule files. |
| `loader` | `PatternLoader` | Default loader | Loads rules from files. |
| `detector_type` | `DetectorType` or `str` | `"regex"` | Selects the detection mode. |
| `default_rules` | `DefaultRules` or `str` | `None` | Library-provided rule set. |
| `model` | `ModelConfig` | `None` | Model configuration for model detection. |
| `provider` | `ModelProviderName` or `str` | `None` | Provider whose default model is resolved from `default_rules`. |
| `rule_strategy` | `RuleStrategy` or `str` | `"precedence"` | Resolves explicit rules and defaults. |
| `combination_strategy` | `CombinationStrategy` or `str` | `"any"` | Combines regex and model results in mixed mode. |
| `inference_engine` | `InferenceEngine` | Default engine | Runs model inference. |

Raises `ConfigurationError` when:

- `detector_type` is not `"regex"`, `"model"`, or `"mixed"`.
- `default_rules` is not one of `"prompt_injection"`, `"pii"`, `"secrets"`, or `None`.
- `combination_strategy` is not one of `"any"`, `"all"`, or `"precedence"`.
- `rule_strategy` is not `"precedence"` or `"extend"`.
- `provider` is not `"huggingface"`, `"api"`, or `None`.
- `model` is given but is not a `ModelConfig`.
- `provider` contradicts `model.provider`.
- A regex or mixed detector has no `patterns`, no `pattern_paths`, and no `default_rules`.
- A model or mixed detector has no `model` and no `default_rules` with a default model for the requested provider.

## Detection Modes

The `detector_type` parameter selects the detection mode.

### Regex Detection Mode

`detector_type="regex"` evaluates regex rules only.
This is the default mode.

```python
from qarai_agent_guard import Detector

detector = Detector(name="pii", default_rules="pii")
print(detector.detector_type)  # DetectorType.REGEX
```

### Model Detection Mode

`detector_type="model"` performs model inference only.
Regex rules are not loaded.

The detector needs a model configuration.

#### HuggingFace Provider

For models hosted on HuggingFace, the default provider is `"huggingface"`. You can use a library default model for HuggingFace:

```python
detector = Detector(
    name="model_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
)
```

This uses the HuggingFace default model because the provider defaults to `"huggingface"`.

You can also pass an explicit model configuration:

```python
from qarai_agent_guard.core.models import resolve_default_model

detector = Detector(
    name="model_prompt_injection",
    detector_type="model",
    model=resolve_default_model("prompt_injection"),
)
```

To explicitly specify the HuggingFace provider:

```python
detector = Detector(
    name="hf_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
    provider="huggingface",
)
```

#### API-Based Provider

For models accessed through API endpoints, you must specify `provider="api"`. The library supports different API providers, including OpenRouter, vLLM, and Ollama.

##### API Detection Behaviour (Default)

The default API configuration (used with `default_rules="prompt_injection"` and `provider="api"`) expects the model to answer with exactly one word: `safe` or `unsafe`.

When using an API-based model, the following default behaviour applies:

| Situation | Behaviour |
| --- | --- |
| The value is empty text | No request. `matched=False` and no `metadata["model"]`. |
| The model answers `unsafe` | `matched=True` with the model severity (defaults to `CRITICAL` for unsafe results). |
| The model answers `safe` | `matched=False`. |
| The endpoint fails | The provider exception leaves `inspect`. |
| The answer has no usable text | `ModelOutputError` leaves `inspect`. |

The guard wraps these errors in `DetectorExecutionError`. The `fail_behavior` setting then decides between `ALLOW` and `BLOCK`. See [Security Modes and Runtime Behaviour](runtime.md).

##### Provider Rules

Before configuring specific providers, note the following rules:

- `provider` accepts `"huggingface"`, `"api"`, or `None`.
- An unknown value raises `ConfigurationError`.
- `provider` must match `model.provider` when both are set.
- A mismatch raises `ConfigurationError`.
- `provider` only selects the default model. It does not change the detection mode.
- The `Detector` constructor has no `api_key` parameter.

If you specify `default_rules="pii"` with `provider="api"` and no explicit model, this raises `ConfigurationError` because there is no API default model for the PII rule set.

If you build an API detector from defaults without adding an API key, the first inspection raises `ModelLoadError`. The cause is `api_key is required for API provider`.

##### OpenRouter

To use OpenRouter, specify the OpenRouter endpoint, model name, and your API key. The model must answer with `safe` or `unsafe` for the default behaviour:

```python
import os
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="gpt-oss-120b",
    task="text-generation",
    threshold=0.5,
    api_key=os.environ["OPENROUTER_API_KEY"],
    model_options={
        "endpoint": "https://openrouter.ai/api/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)

detector = Detector(
    name="openrouter_prompt_injection",
    detector_type="model",
    model=config,
)
```

##### vLLM

To use a self-hosted vLLM server, specify the vLLM endpoint. You may not need an API key if running locally without authentication. Ensure the model follows the `safe`/`unsafe` response format:

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="meta-llama/Meta-Llama-3-8B-Instruct",
    task="text-generation",
    threshold=0.5,
    api_key="",  # Set empty string if no auth is required
    model_options={
        "endpoint": "http://localhost:8000/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)

detector = Detector(
    name="vllm_prompt_injection",
    detector_type="model",
    model=config,
)
```

##### Ollama

To use Ollama, specify the Ollama OpenAI-compatible endpoint. Ollama typically does not require an API key. Ensure the model follows the `safe`/`unsafe` response format:

```python
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="llama3.2",
    task="text-generation",
    threshold=0.5,
    api_key="",  # Ollama typically does not require API key
    model_options={
        "endpoint": "http://localhost:11434/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)

detector = Detector(
    name="ollama_prompt_injection",
    detector_type="model",
    model=config,
)
```

Model and mixed modes both work with API-based models.

See [Model-Based Detection](models.md) for the `ModelConfig` reference and the full API-based provider reference.

### Mixed Detection Mode

`detector_type="mixed"` performs regex detection and model inference.
The `combination_strategy` parameter combines the two results.

```python
detector = Detector(
    name="mixed_prompt_injection",
    detector_type="mixed",
    default_rules="prompt_injection",
    combination_strategy="any",
)
```

## Rule Sources

A detector gets its regex rules from three sources:

| Source | Parameter | Role |
| --- | --- | --- |
| Inline patterns | `patterns` | Rules defined directly in Python. |
| Pattern files | `pattern_paths` | Rules loaded from YAML files. |
| Default rules | `default_rules` | Rules shipped with the library. |

### Inline patterns

Pass rules as a list of dictionaries:

```python
detector = Detector(
    name="project_codename",
    patterns=[
        {
            "id": "unreleased_codename",
            "name": "Unreleased Project Codename",
            "severity": "medium",
            "pattern": r"\b(?:Aurora|Phoenix|Nimbus)-?\d{0,4}\b",
        },
        {
            "id": "confidential_marker",
            "name": "Confidential Marker",
            "severity": "high",
            "pattern": r"\bTOP SECRET\b",
        },
    ],
)
```

Each rule requires four fields:

| Field | Type | Role |
| --- | --- | --- |
| `id` | `str` | Stable rule identifier. |
| `name` | `str` | Human-readable rule name. |
| `severity` | `str` | One of `info`, `low`, `medium`, `high`, `critical`. |
| `pattern` | `str` | The regex expression. |

### Pattern files

Point a detector at one or more YAML files:

```python
from pathlib import Path

detector = Detector(
    name="custom",
    pattern_paths=[Path("detector_rules.yaml")],
)
```

### Default rules

`default_rules` selects a library-provided rule set.

| Value | Rule set |
| --- | --- |
| `"prompt_injection"` | Language rules plus XML injection rules. |
| `"pii"` | PII rules: cards, IBAN, email, phone, passport. |
| `"secrets"` | Secrets rules: API keys, tokens, credentials. |

See [Detection Patterns](patterns.md) for the full rule listings.

## Rule Resolution

The `rule_strategy` parameter defines how the rule sources combine.

Each strategy accepts the enum member `RuleStrategy.PRECEDENCE` or `RuleStrategy.EXTEND`, or the strings `"precedence"` and `"extend"`.

### Precedence strategy

`rule_strategy="precedence"` uses the first explicit source in this order:

1. Inline `patterns`
2. `pattern_paths`
3. `default_rules`

Rules from the earlier sources are used.
Rules from the later sources are ignored.

### Extend strategy

`rule_strategy="extend"` combines all sources in this order:

1. `default_rules`
2. Rules loaded from `pattern_paths`
3. Inline `patterns`

Example: combine the PII default rules with an extra rule:

```python
detector = Detector(
    name="pii_ext",
    default_rules="pii",
    rule_strategy="extend",
    patterns=[{"id": "employee_id", "name": "Employee ID", "severity": "high", "pattern": r"\bEMP-\d{6}\b"}],
)
```

## Languages

The `lang` parameter selects the language for language-dependent rules.
The `prompt_injection` default rule set loads the language file for the selected language.

Supported values:

| Value | Language |
| --- | --- |
| `"en"` | English (default) |
| `"fr"` | French |
| `"ar"` | Arabic |

```python
fr_detector = Detector(
    name="prompt_injection_fr",
    default_rules="prompt_injection",
    lang="fr",
)

ar_detector = Detector(
    name="prompt_injection_ar",
    default_rules="prompt_injection",
    lang="ar",
)
```

Raises `ValueError` for an unsupported language code.

## Inspect

`inspect` checks a value for configured threats.

```python
result = detector.inspect(
    key="payload",
    value="Please store IBAN FR1420041010050500013M02606.",
    operation="write",
)
```

Parameters:

| Parameter | Type | Role |
| --- | --- | --- |
| `key` | `str` | Logical name or path of the value. |
| `value` | `Any` | The value to inspect. |
| `operation` | `str` | The operation on the value, for example `"write"`. |

The detector converts the value to text before detection.

Returns a `DetectionResult` with these fields:

| Field | Type | Role |
| --- | --- | --- |
| `detector` | `str` | The detector name. |
| `matched` | `bool` | Whether any rule or model matched. |
| `message` | `str` | A summary message. |
| `matches` | `list[Match]` | The individual rule hits. |
| `metadata` | `dict` | Extra context for policy evaluation. |
| `model_detection_result` | `ModelDetectionResult` or `None` | The model outcome for model and mixed modes. |

A `Match` has these fields:

| Field | Type | Role |
| --- | --- | --- |
| `pattern_id` | `str` | The id of the matched rule. |
| `pattern_name` | `str` | The name of the matched rule. |
| `severity` | `str` | The rule severity. |
| `match` | `str` | The matched text span. |

The `metadata` dictionary always contains:

| Key | Type | Role |
| --- | --- | --- |
| `language` | `str` | The detector language. |
| `operation` | `str` | The operation name. |
| `hit_count` | `int` | The number of rule hits. |

For model and mixed modes, `metadata["model"]` contains:

| Key | Type | Role |
| --- | --- | --- |
| `provider` | `str` | The model provider. It is `"huggingface"` or `"api"`. |
| `name` | `str` | The model identifier. |
| `score` | `float` | The detection score. |
| `severity` | `str` | The model severity. |

The key `metadata["model"]` is missing when the value is empty text.
The detector returns before it calls the model.

Raises:

- `TypeError` if `key` or `operation` is not a string.
- `ValueError` if `key` or `operation` is empty.

Example with a PII detector:

```python
from qarai_agent_guard import Detector

detector = Detector(name="pii", default_rules="pii")

result = detector.inspect(
    key="payload",
    value="Contact jhon.smith@yahoo.com to schedule the demo.",
    operation="write",
)

print(result.matched)             # True
print(result.message)             # PII pattern detected in 'payload'
print(result.matches[0].pattern_id)  # email
```

A value with no matches returns `matched=False`:

```python
result = detector.inspect(
    key="payload",
    value="What is machine learning?",
    operation="write",
)

print(result.matched)  # False
```

## Redact

`redact` replaces sensitive data with markers.

For regex rules, the detector replaces each match with a marker of this format:

```text
[REDACTED:<rule_id>]
```

Example:

```python
redacted = detector.redact(
    "Contact jhon.smith@yahoo.com"
)

print(redacted)
# Contact [REDACTED:email]
```

The `entities` parameter adds model-detected entities:

| Parameter | Type | Default | Role |
| --- | --- | --- | --- |
| `value` | `Any` | Required | The value to redact. |
| `entities` | `list[dict]`, `ModelDetectionResult`, `DetectionResult` | `None` | Model entities to redact. |

Each entity must contain `start` and `end` offsets.
The detector uses `entity_group` as the label when available.

The detector replaces model entities in reverse positional order.
Earlier replacements do not invalidate the offsets of later entities.

Example:

```python
detector = Detector(name="model_pii", detector_type="model", default_rules="pii")

text = "My name is Jhon Smith and my email is jhon.smith@yahoo.com."

result = detector.inspect(key="profile", value=text, operation="write")
redacted = detector.redact(text, entities=result.model_detection_result)
```

The detector logs a warning when you call `redact` on a model-only detector without entities.

## Messages

The message depends on the detection mode and the rule set in use.

Regex messages:

| Rule set | Message |
| --- | --- |
| `pii` | `PII pattern detected in '<key>'` |
| `secrets` | `Secrets pattern detected in '<key>'` |
| `prompt_injection` | `Prompt injection pattern detected in '<key>'` |
| `None` (custom rules) | `Security check detected a possible issue in '<key>'` |

Model messages:

```text
Model detected a potential <default_rules with underscores replaced by spaces> in '<key>'
```

For example, with `default_rules="prompt_injection"`:

```text
Model detected a potential prompt injection in '<key>'
```

Mixed-mode messages:

| Condition | Message |
| --- | --- |
| Regex hits and model detection | `Security issue detected in '<key>'` |
| Regex hits only | The regex message for the rule set |
| Model detection only | The model message |

## Complete Examples

Regex detector with PII rules:

```python
from qarai_agent_guard import Detector

detector = Detector(name="pii", default_rules="pii")
```

Model detector with the default HuggingFace prompt-injection model:

```python
detector = Detector(
    name="model_prompt_injection",
    detector_type="model",
    default_rules="prompt_injection",
)
```

Mixed detector with custom patterns and a HuggingFace model:

```python
from qarai_agent_guard.core.models import resolve_default_model

detector = Detector(
    name="mixed_custom",
    detector_type="mixed",
    patterns=[
        {
            "id": "magic_token",
            "name": "Magic Token",
            "severity": "high",
            "pattern": r"\bmagic-token-42\b",
        },
    ],
    model=resolve_default_model("prompt_injection"),
    combination_strategy="any",
)
```

Model detector with a remote API model (example using OpenRouter):

```python
import os
from qarai_agent_guard.core.models import ModelConfig

config = ModelConfig(
    provider="api",
    model="gpt-oss-120b",
    task="text-generation",
    threshold=0.5,
    api_key=os.environ["OPENROUTER_API_KEY"],
    model_options={
        "endpoint": "https://openrouter.ai/api/v1",
        "messages": [
            {
                "role": "system",
                "content": "You are a security classifier. Answer with exactly one word: safe or unsafe.",
            }
        ],
    },
    inference_options={
        "temperature": 0.0,
        "max_tokens": 256,
    },
)

detector = Detector(
    name="api_injection",
    detector_type="model",
    model=config,
)
```

Detector with a custom YAML pattern file:

```python
from pathlib import Path

detector = Detector(
    name="custom",
    pattern_paths=[Path("detector_rules.yaml")],
)
```

Secret detector:

```python
detector = Detector(name="secrets", default_rules="secrets")
```
