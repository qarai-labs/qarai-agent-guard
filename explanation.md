# Qarai Agent Guard: Project Explanation

## 1. Purpose and mental model

Qarai Agent Guard is a Python security library for inspecting arbitrary agent or memory payloads before they are accepted, sent to a model, returned by a model, or passed to a tool. Its core responsibility is to separate three concerns:

1. **Detection**: `Detector` instances inspect text with regex rules, a model, or both and return structured `DetectionResult` objects.
2. **Decision**: a `Policy` maps the matched results to a `PolicyDecision` such as allow, warn, redact, block, or quarantine.
3. **Enforcement and integration**: `AgentGuard` orchestrates detectors and policy, while the LangChain and CrewAI packages connect that pipeline to framework lifecycle hooks.

The normal synchronous path is:

```text
payload
  -> Detector.inspect()
  -> DetectionResult(s)
  -> Policy.evaluate()
  -> PolicyDecision
  -> optional SecurityEvent(s)
  -> integration-specific enforcement
```

The core package does not itself mutate or reject the caller's payload during `inspect`. It returns a decision. Callers explicitly call `apply_redactions`, or an integration adapter applies the decision at its framework boundary.

## 2. Repository layout

```text
src/qarai_agent_guard/                 Core distributable package
  __init__.py                          Public re-exports
  core/
    detectors/                         Regex/model/mixed detection
    exceptions/                        Core exception hierarchy
    guards/                            AgentGuard orchestration
    helpers/                           Stringification and severity helpers
    loaders/                           YAML pattern and policy loading
    models/                            Model configuration, inference, providers
    policies/                           Policy protocol and built-ins
    schemas/                            Enums and result/event/config structures

integrations/qarai-agent-guard-langchain/
  qarai_agent_guard_langchain/         LangChain middleware package
  tests/                               Middleware tests

integrations/qarai-agent-guard-crewai/
  qarai_agent_guard_crewai/            CrewAI adapter and global hooks
  tests/                               Adapter/hook tests

tests/                                 Core unit and integration tests
assets/                                README assets
README.md                              User-facing quickstart and examples
pyproject.toml                         Build, dependencies, lint, pytest config
```

The root package requires Python 3.11 or newer. The core package depends on PyYAML, Pydantic, Hugging Face/Transformers, Torch, and related model tooling. The CrewAI integration is a workspace member; LangChain is a separate integration package with its own dependency metadata.

## 3. Public API

`src/qarai_agent_guard/__init__.py` re-exports the main symbols so applications normally import from `qarai_agent_guard`:

- `Detector`
- `AgentGuard`
- `Policy`, `PolicyDecision`, `SeverityPolicy`, `SeverityRule`
- `default_policy`, `strict_policy`, `permissive_policy`
- `Action`, `Severity`, `SecurityMode`
- `PolicyLoader`, `PolicyLoaderError`
- `DetectorType`, `DefaultRules`
- `ModelConfig`, `ModelDetectionResult`

The current source exposes one configurable `Detector` class. The README contains examples using names such as `ModelReasoningDetector`, `PIIDetector`, and `SecretsDetector`; those names are not re-exported by the current implementation. New documentation or examples should use `Detector(default_rules=...)` unless those convenience classes are added deliberately.

## 4. Core data model

### 4.1 Enums in `core/schemas/events.py`

All are `StrEnum`, so their values are also useful as strings.

- `Severity`: ordered levels `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. The declaration order is used by severity helpers for comparisons.
- `Action`: `ALLOW`, `WARN`, `REDACT`, `BLOCK`, `QUARANTINE`.
- `SourceClass`: payload provenance: `EXTERNAL_TOOL`, `USER_INPUT`, `AGENT_AUTHORED`, `SYSTEM`, `UNKNOWN`.
- `EventType`: `DETECTION`, `SYSTEM_FAILURE`, `CALLBACK_FAILURE`, `POLICY_FAILURE`.

### 4.2 `Match`

File: `core/schemas/detection.py`

A slots dataclass representing one regex hit:

- `pattern_id: str`: stable rule identifier.
- `pattern_name: str`: readable rule name.
- `severity: str`: severity copied from the YAML/inline rule.
- `match: str`: exact text returned by the regular expression.

### 4.3 `DetectionResult`

A slots dataclass representing one detector's inspection:

- `detector: str`: detector name.
- `matched: bool`: whether this detector considers the payload unsafe.
- `message: str`: readable reason; empty for a non-match.
- `matches: list[Match]`: regex hits.
- `metadata: dict[str, Any]`: language, operation, hit count, model details, and custom context.
- `model_detection_result: ModelDetectionResult | None`: normalized model result when model detection ran.

`AgentGuard` only sends matched results to policy evaluation. Therefore a detector may return an unmatched result for direct callers, but `run_detectors` filters it out.

### 4.4 `PolicyDecision` and `SeverityRule`

File: `core/schemas/policy.py`

- `PolicyDecision` is a slots dataclass with `action: Action` and an optional `reason: str`.
- `SeverityRule` is a frozen slots dataclass with `severities: tuple[Severity, ...]` and `action: Action`.

A policy is structurally typed through the `Policy` protocol in `core/policies/base.py`: it only needs an `evaluate(results: list[DetectionResult]) -> PolicyDecision` method.

### 4.5 `SecurityEvent`

File: `core/schemas/events.py`

A serializable dataclass recording an emitted event:

- Required fields: `detector`, `severity`, `action`, `key`, and `message`.
- Context fields: `operation` (default `write`), `source_class` (default `UNKNOWN`), `receipt_uri`, and arbitrary `metadata`.
- Generated fields: `timestamp` defaults to `time.time()`, `event_id` defaults to a UUID, and `event_type` defaults to `DETECTION`.

`to_dict()` converts enum values to strings and returns a plain dictionary suitable for logging or SIEM forwarding. `AgentGuard.events` retains emitted events in process memory.

## 5. `Detector`: detection boundary

File: `src/qarai_agent_guard/core/detectors/detector.py`

`Detector` is the main extension point for content detection. It supports:

- `detector_type="regex"`: compile and search rules only.
- `detector_type="model"`: run an inference engine only; regex rules are not loaded.
- `detector_type="mixed"`: run both and combine their boolean results.

### Constructor arguments and stored attributes

- `lang`: canonicalized by `normalize_language`; currently `en`, `fr`, and `ar`.
- `name`: custom detector name, otherwise class attribute `"detector"`.
- `patterns`: inline rule mappings.
- `pattern_paths`: YAML files containing rules.
- `loader`: optional `PatternLoader`; otherwise one rooted at `PATTERNS_ROOT`.
- `detector_type`: converted to `DetectorType` and stored publicly.
- `default_rules`: optional `DefaultRules` value (`prompt_injection`, `pii`, `secrets`).
- `model`: explicit `ModelConfig`; it takes precedence over a default model.
- `rule_strategy`: `precedence` or `extend`.
- `combination_strategy`: `any`, `all`, or `precedence` for mixed detection.
- `inference_engine`: injectable `InferenceEngine`, useful for tests and shared model caches.

Internal attributes:

- `_language`: normalized language code.
- `_rule_strategy`: rule resolution mode.
- `_combination_strategy`: enum form of the combination strategy.
- `_model_config`: explicit model or `resolve_default_model(default_rules)`.
- `_model_engine`: an `InferenceEngine` for model/mixed detectors; `None` for regex-only detectors.
- `_loader`: pattern loader.
- `_rules`: final validated rule mappings.
- `_compiled`: compiled regular expressions corresponding positionally to `_rules`.

The constructor validates enum-like configuration and ensures regex detectors have at least one rule source. Model and mixed detectors must have a model either explicitly or through a model-backed default rule set.

### Rule resolution

`_resolve_rules(patterns, pattern_paths, loader)` implements two modes:

- `extend`: concatenate default rules, rules loaded from `pattern_paths`, then inline `patterns`.
- `precedence`: use the first configured source in this order: inline `patterns`, `pattern_paths`, then default rules. An explicitly empty list is still an explicit source.

`_load_default_rules(loader)` maps built-ins as follows:

- `PII` -> `core/detectors/patterns/common/pii.yaml`.
- `SECRETS` -> `common/secrets.yaml`.
- `PROMPT_INJECTION` -> language-specific `model_reasoning.yaml` plus common `xml_injection.yaml`.

Default model configuration is separate from regex rule loading. `prompt_injection` has a text-classification default model; `pii` has a token-classification default model; `secrets` has no default model.

### Methods

#### `inspect(key, value, *, operation) -> DetectionResult`

1. Validates non-empty string `key` and `operation`.
2. Converts arbitrary `value` to text using `_stringify`.
3. Searches every compiled regex with `pattern.search`, producing `Match` objects.
4. Runs model inference for model/mixed detectors.
5. Combines regex and model booleans.
6. Builds a message and metadata.
7. Returns a `DetectionResult`.

Empty text returns an unmatched result with language, operation, and `hit_count=0`. Model metadata includes provider, model name, score, and normalized severity.

#### `redact(value, entities=None) -> str`

Converts the value to text, applies every configured regex substitution as `[REDACTED:<rule id>]`, then applies model entities in descending `start` offset order. Reverse ordering prevents an earlier replacement from shifting later offsets.

`entities` may be a list of dictionaries, a `ModelDetectionResult`, or a `DetectionResult`. Entity dictionaries need integer `start` and `end`; `entity_group` supplies the marker label and defaults to `MODEL`. Model-only redaction without entities logs a warning and cannot redact model spans.

#### `_validate_config(...)`

Converts detector, default-rule, and combination values to enums; validates `rule_strategy`; and requires `ModelConfig` when a model is supplied.

#### `_combine_results(hits, model_result) -> bool`

Regex mode means `bool(hits)`. Model mode means `model_result.detected`. Mixed `any` is OR, `all` is AND, and `precedence` uses regex detection only.

#### `_build_message`, `_build_regex_message`, `_build_model_message`

Select readable messages based on detector type and default rule. Mixed detections use a generic combined message when both sources detect.

#### `_validate_input(key, operation)` and `_validate_entities(entities)`

Static validators for inspection identifiers and model redaction offsets. They raise `TypeError` for wrong primitive types and `ValueError` for empty or malformed values.

## 6. `AgentGuard`: orchestration and failure policy

File: `core/guards/agent_guard.py`

`AgentGuard` owns the detector list, policy, execution semantics, disabled-detector set, event history, and callbacks.

### Constructor attributes

- `detectors`: mutable list of uniquely named `Detector` instances.
- `policy`: supplied policy or a new `default_policy()`.
- `fail_behavior`: `FAIL_OPEN` or `FAIL_CLOSED`.
- `security_mode`: `ENFORCE` or `MONITOR`.
- `execution_strategy`: `EXHAUSTIVE` or `FAIL_FAST`.
- `events`: emitted `SecurityEvent` objects.
- `_disabled`: detector names temporarily skipped.
- `event_callbacks`: callbacks receiving each successfully emitted event.

The constructor validates list types, detector types, unique names, callable callbacks, and enum values.

### Construction and detector management

- `create(...)`: class factory. If `policy` is absent and `policy_path` is supplied, loads a YAML policy through `PolicyLoader` before constructing the guard.
- `register_detector(detector)`: appends a new uniquely named detector.
- `unregister_detector(name)`: removes by name and clears its disabled state.
- `disable_detector(name)`: keeps the detector but skips it during detection and redaction.
- `enable_detector(name)`: removes its disabled marker.
- `register_callback(callback)`: adds an event callback.

All name-based methods raise `ValueError` for unknown names; registration raises for invalid or duplicate detectors.

### Detection flow methods

#### `run_detectors(*, key, value, operation, errors=None)`

Runs active detectors in list order and returns only matched results. Detector exceptions are wrapped as `DetectorExecutionError` and optionally appended to `errors`. `FAIL_FAST` stops after the first match or first failure; `EXHAUSTIVE` continues.

#### `inspect(...) -> PolicyDecision`

Thin convenience method that calls `inspect_with_results` and discards detections.

#### `inspect_with_results(...) -> (PolicyDecision, list[DetectionResult])`

This is the controlling pipeline:

1. Validate `key`, `operation`, and `source_class`.
2. Run detectors and collect execution errors.
3. Emit critical `SYSTEM_FAILURE` events for detector errors. Under fail-closed, return a blocking decision immediately; under fail-open, continue and eventually allow if no other detection blocks.
4. Call `policy.evaluate(detections)`. Policy exceptions emit a `POLICY_FAILURE`; fail-closed re-raises `PolicyEvaluationError`, while fail-open returns allow with the error as the reason.
5. In monitor mode, convert block or redact decisions to allow and prefix the reason with `[MONITOR]`.
6. If `emit_events=True`, emit one `DETECTION` event per matched result using its highest severity.
7. Return the decision and matched results.

`request_metadata` is copied into event metadata, then result metadata is merged over it for detection events.

#### `check(key, value, operation)`

Adapter-oriented wrapper around `inspect_with_results` with event emission always enabled. It returns both decision and detections.

### Redaction and events

#### `apply_redactions(value, *, severity_threshold=None, detections=None)`

Walks active detectors and calls their `redact` method. If prior detections include model entities, those entities are passed to the matching detector. A severity threshold restricts redaction to detectors whose highest result severity meets the threshold.

Redaction errors emit critical system-failure events. Fail-open keeps the partially redacted value; fail-closed raises `RedactionError`. The method has a compatibility fallback for detector implementations whose `redact` does not accept `entities=`.

#### `_emit_event(...) -> SecurityEvent`

Constructs and stores a `SecurityEvent`, then invokes callbacks. A callback exception is printed to stderr and represented as a `CALLBACK_FAILURE` warning event; callback failures do not recursively invoke callbacks.

#### `_validate_key`, `_validate_operation`, `_coerce_enum`

Static/shared validation helpers for public inputs and enum-like constructor values.

### Operational semantics to preserve

- Fail-open and monitor mode are distinct. Fail-open handles implementation failures; monitor mode intentionally observes policy violations without blocking/redacting.
- `QUARANTINE` can be returned by a custom policy, but core `AgentGuard` only returns the decision. Integrations decide how to quarantine.
- Detector names are the identity used by disabling, redaction entity routing, and event metadata.

## 7. Policies

File: `core/policies/base.py`

### `Policy` protocol

A minimal structural interface with `evaluate(results)`. Custom policies can use detector names, match metadata, source context supplied elsewhere, or their own action logic, as long as they return `PolicyDecision`.

### `SeverityPolicy`

Attributes:

- `name`: non-empty policy name.
- `rules`: non-empty ordered list of `SeverityRule` objects.
- `default_action`: fallback action.

`evaluate(results)` allows an empty list, finds the highest severity across all results, then returns the action of the first rule containing that severity. If no rule matches, it uses `default_action`. `_build_reason` prefers a message from a result at the highest severity, then any message, then a generated severity string.

`severity_rule_from_mapping(mapping)` converts YAML-like dictionaries with `severities` and `action` into a `SeverityRule`. It parses severity strings case-insensitively and validates actions.

### Built-in policies

File: `core/policies/defaults.py`

- `default_policy()`: high/critical -> block; medium -> redact; low/info -> warn; otherwise allow.
- `strict_policy()`: medium and above -> block; low/info -> warn.
- `permissive_policy()`: critical -> block; high/medium -> warn; otherwise allow.

`DefaultPolicy` is the concrete implementation used automatically by `AgentGuard`.

## 8. Pattern loading and built-in rules

File: `core/loaders/pattern_loader.py`

`PatternLoader(root)` stores the base path used for relative pattern files. `load_file` resolves and parses YAML, verifies the file and top-level mapping, and returns raw data. `validate_rules(rules, source)` requires each rule to contain string fields `id`, `name`, `severity`, and `pattern`, and accepts only info/low/medium/high/critical severity. `load_patterns(path)` extracts and validates the top-level `rules` list.

`PatternLoaderError` is a `ValueError` for invalid files or rules. YAML syntax errors are allowed to originate from PyYAML.

Built-in rule files are under `core/detectors/patterns`:

- `common/pii.yaml`
- `common/secrets.yaml`
- `common/xml_injection.yaml`
- `languages/en/model_reasoning.yaml`
- `languages/fr/model_reasoning.yaml`
- `languages/ar/model_reasoning.yaml`

Language selection is deliberately exact after lowercasing. There is no fallback from a missing language file to English.

## 9. Model subsystem

### `ModelConfig`

File: `core/schemas/models.py`

A frozen slots dataclass describing provider loading and inference:

- `provider`: currently only `huggingface`.
- `model`: non-empty model identifier or local path.
- `task`: `text-classification`, `token-classification`, `text-generation`, or `text2text-generation`.
- `threshold`: numeric value in `[0, 1]`.
- `hf_access_token`, `api_key`: provider credentials; API key is reserved.
- `output_formatter`: optional callable `(raw_output, config) -> ModelDetectionResult`.
- `model_options`, `tokenizer_options`: loading options.
- `inference_options`: call/generation options.
- `options`: deprecated compatibility field migrated into `inference_options` with a warning.

`__post_init__` normalizes provider/task enums and validates all fields. Because the dataclass is frozen, normalization uses `object.__setattr__`.

### `ModelDetectionResult`

Slots dataclass with `detected: bool`, optional `score`, optional `severity`, arbitrary `metadata`, and `entities`. Missing severity defaults to critical for a detection and low otherwise. String severities are converted to `Severity`; entities must be a list.

### Default model resolution

`core/models/config.py:resolve_default_model(default_rules)` maps `prompt_injection` to `deepset/deberta-v3-base-injection` and `pii` to `SoelMgd/bert-pii-detection`. It returns `None` for `secrets` or invalid/absent rules. The default prompt-injection formatter recognizes injection labels and scores; the PII formatter filters `O`/empty labels and below-threshold entities, preserving entity offsets for redaction.

### `ModelProvider` and `HuggingFaceProvider`

File: `core/models/providers/base.py`

`ModelProvider` is an abstract boundary with `config`, `load()`, `predict(text)`, and `unload()`.

File: `core/models/providers/huggingface.py`

`HuggingFaceProvider` owns `_pipeline`. `load()` maps `ModelTask` to a Transformers pipeline task, forwards model/tokenizer/pipeline options and token/device settings, and loads lazily. `predict(text)` validates text, loads if needed, forwards `inference_options`, and returns raw output unchanged. `unload()` clears the pipeline and attempts to release CUDA cache.

`ModelProviderFactory.create(config)` validates `ModelConfig`, currently selects `HuggingFaceProvider`, and is the provider extension point for future backends.

### `ModelLoader`

File: `core/models/loader.py`

Attributes:

- `_cache: dict[str, ModelProvider]`: loaded providers.
- `_lock`: thread lock protecting cache operations.

`_key(config)` serializes provider, model, task, model options, and tokenizer options. Threshold, formatter, and inference options intentionally do not create a second loaded provider. `get(config)` loads lazily under the lock and caches only successful providers. `release(config)` removes and unloads one provider. `clear()` unloads every cached provider and reports aggregate cleanup failure.

Sharing one `ModelLoader` through multiple `InferenceEngine`/`Detector` instances shares model providers and avoids duplicate loads. Model loading is expensive and may require network access and local cache storage.

### `DefaultOutputFormatter`

File: `core/models/engine.py`

`format(raw, config)` recognizes booleans, integer 0/1, numeric scores, text-classification dictionaries, token-classification entity lists, and generation dictionaries. It produces `ModelDetectionResult`, applying the threshold and critical/low severity convention.

Private shape and formatting methods:

- `_looks_like_text_classification`
- `_looks_like_token_classification`
- `_looks_like_generation`
- `_format_text_classification`
- `_format_token_classification`
- `_format_generation`

Generation output is interpreted with a small positive/negative vocabulary. Custom model heads or ambiguous label semantics should provide `ModelConfig.output_formatter`.

### `InferenceEngine`

Owns a `ModelLoader`. `predict(text, config)` obtains a provider, invokes it, applies the custom formatter or singleton default formatter, preserves `ModelOutputError`, wraps other formatter failures as `ModelFormatterError`, and requires a `ModelDetectionResult` return value.

## 10. Helpers and exceptions

### Stringification

`core/helpers/stringify.py:_stringify` converts strings directly, `None` to an empty string, and lists/tuples/sets/dicts recursively to newline-separated text. It tracks object IDs to detect cycles and enforces `DEFAULT_MAX_DEPTH = 50`. `StringifyError` protects the detector from hostile or broken `__str__`/`__repr__` methods.

### Severity helpers

`core/helpers/detection_utils.py` provides:

- `normalize_language(lang)`
- `parse_severity(value)`
- `highest_match_severity(matches)`
- `highest_result_severity(result)`, combining regex severity and model severity
- `highest_results_severity(results)`

The helpers use the declaration order of `Severity`, so changing enum order changes policy behavior.

### Core exceptions

File: `core/exceptions/__init__.py`

`GuardError` is the base. `ConfigurationError` also subclasses `ValueError`. Model-specific failures are `ModelProviderError`, `ModelLoadError`, `ModelInferenceError`, `ModelOutputError`, and `ModelFormatterError`. Pipeline failures are `DetectorExecutionError`, `PolicyEvaluationError`, and `RedactionError`.

## 11. LangChain integration

Package: `integrations/qarai-agent-guard-langchain`

`AgentGuardMiddleware` subclasses LangChain's `AgentMiddleware` and stores:

- `guard`
- booleans `scan_input`, `scan_output`, `scan_tool_calls`, `scan_tool_results`
- optional `quarantine_handler`
- private `_violations`

Properties are `name` (`AgentGuardMiddleware`) and `violation_count`.

`_extract_content(message)` returns string content or stringifies non-string content. `_enforce_decision(...)` is the sole enforcement point:

- allow -> return content;
- warn -> emit a middleware event and return content;
- redact -> call `guard.apply_redactions` when detections exist;
- block -> increment violations and raise `AgentGuardViolation`;
- quarantine -> optionally call the handler, increment violations, then raise.

Lifecycle methods:

- `before_model` scans all messages in the state when input scanning is enabled.
- `abefore_model` delegates asynchronously to `before_model`.
- `after_model` scans the newest `AIMessage` and returns a replacement message if redaction changed it.
- `aafter_model` delegates to `after_model`.
- `wrap_tool_call` scans tool arguments before invoking the handler, then scans the returned `ToolMessage` content.
- `awrap_tool_call` is the async equivalent.

`AgentGuardViolation` is the integration-level exception exposed from the package. The middleware currently calls core private `_emit_event` for warnings, so a refactor should consider a public event API before changing that boundary.

## 12. CrewAI integration

Package: `integrations/qarai-agent-guard-crewai`

### Schema and utilities

`HookName` enumerates `before_llm_call`, `after_llm_call`, `before_tool_call`, and `after_tool_call`; `ALL_HOOKS` contains their string values.

`EnforcementResult` stores `content`, `action`, and flags `blocked` and `redacted`.

`_HookConfig` stores selected hooks, `fail_open`, `on_error`, and `scan_all_messages`.

Utilities support the variability of CrewAI contexts:

- `_get_attr_or_key` reads either an object attribute or dictionary key.
- `_message_to_text` extracts strings and multimodal text parts.
- `_set_message_content` attempts an in-place rewrite and logs if impossible.

### `AgentGuardAdapter`

The adapter owns `guard`, optional `quarantine_handler`, optional `on_violation`, and `_violations`. `violations` exposes the count.

`_emit_safe` makes telemetry best-effort. `_notify_violation` increments the count and safely invokes the violation callback. `enforce(decision, content, detections, source)` applies all actions and returns `EnforcementResult`; redaction failures fall back to blocking, quarantine may return a blocked result when a handler succeeds, and unknown actions block as a precaution.

### `enable_guard`

`global_hooks.enable_guard(...)` validates hook names, builds an adapter and `_HookConfig`, then registers only the selected CrewAI decorators. It supports:

- `fail_open`: swallow unexpected hook errors by default; false raises `AgentGuardHookError`.
- `on_error`: callback receiving hook, error, and context.
- `on_violation`: callback for block/quarantine.
- `quarantine_handler`: callback receiving source, content, and decision.
- `scan_all_messages`: inspect every input message instead of only the latest.

The four registered closures inspect model input, model output, tool input, and tool output. Intentional `AgentGuardViolation` exceptions always propagate; unrelated hook bugs or malformed contexts follow `fail_open`.

## 13. Tests and development workflow

Core tests are grouped by detectors, guards, models, and integration. They cover rule loading, languages, redaction, detector management, execution strategy, events, failures, inspection, policy, validation, security mode, and model behavior. Integration tests marked `integration`/`e2e` load real Hugging Face models and may require network access and model downloads.

Typical checks:

```powershell
uv run pytest -q
uv run ruff check .
uv run pytest tests\integration --run-integration -v
```

The repository's pytest configuration registers `integration` and `e2e` markers, although the exact command-line option for enabling integration tests should be confirmed in the local test configuration before relying on it.

When adding a feature:

1. Start with the narrowest owning abstraction: detector, policy, model provider, or integration adapter.
2. Add a unit test with injected loaders/engines where possible; avoid real model downloads for ordinary unit tests.
3. Preserve structured result metadata and severity so policies and redaction can continue to work.
4. Add failure-path tests for fail-open/fail-closed behavior when touching shared orchestration.
5. Run formatting/lint and the focused test module before the full suite.

## 14. Extension and refactoring guidance

### Add a detector capability

Prefer extending `Detector` only when the behavior is common to regex/model/mixed operation. For a new independent algorithm, implement a detector-compatible class with `name`, `inspect`, and ideally `redact`, then check whether `AgentGuard`'s strict `isinstance(detector, Detector)` validation needs a protocol-based refactor.

### Add a model provider

Implement `ModelProvider`, add a `ModelProviderName` enum member, map it in `ModelProviderFactory`, and define cache-key fields in `ModelLoader._key`. Keep raw provider output unmodified; put normalization in an `InferenceEngine` formatter.

### Add a rule set

Add a `DefaultRules` member, rule files, `_load_default_rules` handling, and optional `resolve_default_model` behavior. Add language and severity tests. Be explicit about whether the set supports regex, model, or both.

### Add policy behavior

Implement the `Policy` protocol or extend `SeverityPolicy`. Keep action selection separate from enforcement so both integrations receive identical decisions. If a new action is added, update `Action`, YAML validation, core consumers, and both adapters.

### Add an integration hook

Keep framework-specific context extraction in the integration package. Reuse `guard.check` for event-producing inspection and one adapter method for action enforcement. Test allow, warn, redact, block, quarantine, callback errors, and fail-open behavior.

## 15. Important current caveats

- The README's convenience detector names do not match the current exported source API.
- `AgentGuard` and the LangChain middleware use private core method `_emit_event`; a public telemetry method would reduce coupling.
- `SourceClass` is strictly validated by `AgentGuard.inspect_with_results`, while some integration warning calls pass the string `"unknown"` directly to `_emit_event`; this works only because the event constructor does not validate it immediately and may be fragile for serialization.
- Model cache identity excludes threshold, output formatter, and inference options by design. Sharing a provider is correct for loading, but callers must understand that formatter and inference behavior belong to the detector/configuration layer.
- Model-only detectors have no regex rules to redact. Entity offsets must be present in `ModelDetectionResult.entities` for model redaction to change text.
- Event history is unbounded in memory. Long-running applications may need an event sink, retention policy, or callback that forwards and clears events.
- `Severity` declaration order is policy-critical. Reordering enum members is a behavior change.
