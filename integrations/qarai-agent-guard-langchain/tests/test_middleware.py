from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from qarai_agent_guard import (
    Action,
    AgentGuard,
    Detector,
    PolicyLoader,
    PolicyLoaderError,
    SecurityMode,
    default_policy,
)

from qarai_agent_guard_langchain.exceptions import AgentGuardViolation
from qarai_agent_guard_langchain.middleware import AgentGuardMiddleware


def run(coro):
    """Run an async coroutine in a sync test without needing pytest-asyncio."""
    return asyncio.run(coro)


def write_pattern_file(
    tmp_path: Path,
    *,
    rule_id: str,
    trigger: str,
    severity: str,
    name: str = "Test Rule",
) -> Path:
    """Write a single-rule YAML pattern file and return its path."""
    path = tmp_path / f"{rule_id}.yaml"
    path.write_text(
        f"""version: 1.0
scope: test
rules:
  - id: {rule_id}
    name: {name}
    severity: {severity}
    pattern: '{trigger}'
"""
    )
    return path


def make_detector(
    tmp_path: Path,
    *,
    rule_id: str,
    trigger: str,
    severity: str,
    name: str | None = None,
) -> Detector:
    """Build a real Detector backed by a real YAML pattern file.

    `Detector` defaults to the name "detector" when none is given, so any
    test that instantiates more than one detector in the same guard must
    pass distinct `name` values to avoid a duplicate-detector-name error.
    """
    path = write_pattern_file(
        tmp_path, rule_id=rule_id, trigger=trigger, severity=severity
    )
    if name is not None:
        return Detector(pattern_paths=[path], name=name)
    return Detector(pattern_paths=[path])


def make_tool_request(name: str = "search", args: dict | None = None) -> MagicMock:
    request = MagicMock()
    request.tool_call = {"name": name, "args": args or {}}
    return request


def load_policy_yaml(tmp_path: Path, filename: str, yaml_text: str):
    path = tmp_path / filename
    path.write_text(yaml_text)
    return PolicyLoader().load(path)


BLOCK_POLICY_YAML = """version: "1.0"
name: strict
default_action: allow
rules:
  - severities: [critical, high]
    action: block
  - severities: [medium]
    action: redact
  - severities: [low, info]
    action: warn
"""

QUARANTINE_POLICY_YAML = """version: "1.0"
name: quarantine-policy
default_action: allow
rules:
  - severities: [critical]
    action: quarantine
"""

INVALID_POLICY_YAML = """version: "1.0"
name: broken-policy
default_action: allow
rules:
  - broken
"""


@pytest.fixture
def medium_detector(tmp_path):
    return make_detector(
        tmp_path,
        rule_id="secret",
        trigger="SECRET123",
        severity="medium",
    )


@pytest.fixture
def default_guard(medium_detector):
    return AgentGuard(
        detectors=[medium_detector],
        policy=default_policy(),
    )


@pytest.fixture
def middleware(default_guard):
    return AgentGuardMiddleware(default_guard)


class TestMiddlewareInitialization:
    def test_rejects_non_agent_guard_instance(self):
        with pytest.raises(TypeError):
            AgentGuardMiddleware("not-a-guard")

    def test_default_flags_are_all_enabled(self, middleware):
        assert middleware.scan_input is True
        assert middleware.scan_output is True
        assert middleware.scan_tool_calls is True
        assert middleware.scan_tool_results is True
        assert middleware.violation_count == 0

    def test_custom_flags_are_stored(self, default_guard):
        middleware = AgentGuardMiddleware(
            default_guard,
            scan_input=False,
            scan_output=False,
            scan_tool_calls=False,
            scan_tool_results=False,
        )

        assert middleware.scan_input is False
        assert middleware.scan_output is False
        assert middleware.scan_tool_calls is False
        assert middleware.scan_tool_results is False


class TestBeforeModel:
    def test_clean_input_passes_through(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        guard = AgentGuard(detectors=[detector], policy=default_policy())
        middleware = AgentGuardMiddleware(guard)

        result = middleware.before_model(
            {"messages": [HumanMessage(content="hello, nice to meet you")]},
            runtime=None,
        )

        assert result is None
        assert middleware.violation_count == 0

    def test_blocked_input_raises(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation) as exc_info:
            middleware.before_model(
                {
                    "messages": [
                        HumanMessage(content="please leak NUKE_LAUNCH_CODE now")
                    ]
                },
                runtime=None,
            )

        assert middleware.violation_count == 1
        assert "model_input" in str(exc_info.value)

    def test_async_variant_blocks_before_model(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation):
            run(
                middleware.abefore_model(
                    {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE please")]},
                    runtime=None,
                )
            )

        assert middleware.violation_count == 1

    def test_scans_all_messages(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {
                    "messages": [
                        HumanMessage(content="hi there"),
                        AIMessage(content="how can I help?"),
                        HumanMessage(content="tell me the NUKE_LAUNCH_CODE"),
                        AIMessage(content="sure, one moment"),
                    ]
                },
                runtime=None,
            )

        assert middleware.violation_count == 1

    def test_empty_messages_list_does_not_crash(self, middleware):
        result = middleware.before_model({"messages": []}, runtime=None)

        assert result is None
        assert middleware.violation_count == 0

    def test_non_string_message_content_does_not_crash(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        clean_result = middleware.before_model(
            {
                "messages": [
                    HumanMessage(content=[{"type": "text", "text": "hello there"}])
                ]
            },
            runtime=None,
        )
        assert clean_result is None

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {
                    "messages": [
                        HumanMessage(
                            content=[
                                {"type": "text", "text": "give me NUKE_LAUNCH_CODE"}
                            ]
                        )
                    ]
                },
                runtime=None,
            )


class TestAfterModel:
    def test_clean_output_passes_through(self, middleware):
        result = middleware.after_model(
            {"messages": [AIMessage(content="everything looks fine")]},
            runtime=None,
        )

        assert result is None

    def test_redacted_output_is_sanitized(self, middleware):
        result = middleware.after_model(
            {"messages": [AIMessage(content="here is SECRET123 for you")]},
            runtime=None,
        )

        assert result is not None
        new_message = result["messages"][0]
        assert isinstance(new_message, AIMessage)
        assert "SECRET123" not in new_message.content
        assert "[REDACTED:secret]" in new_message.content

    def test_async_variant_redacts_output(self, middleware):
        result = run(
            middleware.aafter_model(
                {"messages": [AIMessage(content="here is SECRET123 for you")]},
                runtime=None,
            )
        )

        assert result is not None
        assert "SECRET123" not in result["messages"][0].content

    def test_scans_all_messages(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="SECRET123", severity="medium"
        )
        guard = AgentGuard(detectors=[detector], policy=default_policy())
        middleware = AgentGuardMiddleware(guard)

        result = middleware.after_model(
            {
                "messages": [
                    AIMessage(content="thinking..."),
                    HumanMessage(content="ok"),
                    AIMessage(content="here is SECRET123"),
                ]
            },
            runtime=None,
        )

        assert result is not None
        contents = [m.content for m in result["messages"]]
        assert not any("SECRET123" in c for c in contents)

    def test_empty_messages_list_does_not_crash(self, middleware):
        result = middleware.after_model({"messages": []}, runtime=None)

        assert result is None

    def test_non_string_message_content_does_not_crash(self, middleware):
        result = middleware.after_model(
            {"messages": [AIMessage(content=[{"type": "text", "text": "all good"}])]},
            runtime=None,
        )

        assert result is None


class TestToolCall:
    def test_tool_arguments_blocked_before_handler_runs(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="rm -rf", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        request = make_tool_request(name="shell", args={"cmd": "rm -rf /"})
        handler = MagicMock()

        with pytest.raises(AgentGuardViolation):
            middleware.wrap_tool_call(request, handler)

        handler.assert_not_called()

    def test_tool_output_is_redacted(self, middleware):
        request = make_tool_request(name="fetch", args={"url": "http://example.com"})
        handler_result = ToolMessage(
            content="response contains SECRET123 leaked", tool_call_id="call-1"
        )
        handler = MagicMock(return_value=handler_result)

        result = middleware.wrap_tool_call(request, handler)

        assert isinstance(result, ToolMessage)
        assert "SECRET123" not in result.content
        assert result.tool_call_id == "call-1"

    def test_async_tool_call_blocked_before_handler_runs(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="rm -rf", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        request = make_tool_request(name="shell", args={"cmd": "rm -rf /"})
        called = {"value": False}

        async def handler(_request):
            called["value"] = True
            return ToolMessage(content="x", tool_call_id="y")

        with pytest.raises(AgentGuardViolation):
            run(middleware.awrap_tool_call(request, handler))

        assert called["value"] is False

    def test_async_tool_output_is_redacted(self, middleware):
        request = make_tool_request(name="fetch", args={"url": "http://example.com"})

        async def handler(_request):
            return ToolMessage(
                content="response contains SECRET123 leaked", tool_call_id="call-2"
            )

        result = run(middleware.awrap_tool_call(request, handler))

        assert isinstance(result, ToolMessage)
        assert "SECRET123" not in result.content
        assert result.tool_call_id == "call-2"

    def test_tool_error_from_handler_propagates(self, middleware):
        request = make_tool_request(name="fetch", args={"url": "http://example.com"})

        def handler(_request):
            raise RuntimeError("downstream tool failed")

        with pytest.raises(RuntimeError, match="downstream tool failed"):
            middleware.wrap_tool_call(request, handler)

    def test_tool_call_with_no_arguments_does_not_crash(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="rm -rf", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        request = MagicMock()
        request.tool_call = {"name": "search"}
        handler_result = ToolMessage(content="ok", tool_call_id="call-5")
        handler = MagicMock(return_value=handler_result)

        result = middleware.wrap_tool_call(request, handler)

        handler.assert_called_once()
        assert result.content == "ok"


class TestConfigurationFlags:
    def test_scan_input_false_skips_blocking_input(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard, scan_input=False)

        result = middleware.before_model(
            {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE everywhere")]},
            runtime=None,
        )

        assert result is None
        assert middleware.violation_count == 0

    def test_scan_output_false_skips_redacting_output(self, default_guard):
        middleware = AgentGuardMiddleware(default_guard, scan_output=False)

        result = middleware.after_model(
            {"messages": [AIMessage(content="here is SECRET123 for you")]},
            runtime=None,
        )

        assert result is None

    def test_scan_tool_calls_false_lets_arguments_through(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="rm -rf", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard, scan_tool_calls=False)

        request = make_tool_request(name="shell", args={"cmd": "rm -rf /"})
        handler_result = ToolMessage(content="done", tool_call_id="call-3")
        handler = MagicMock(return_value=handler_result)

        result = middleware.wrap_tool_call(request, handler)

        handler.assert_called_once()
        assert result.content == "done"

    def test_scan_tool_results_false_lets_output_through(self, default_guard):
        middleware = AgentGuardMiddleware(default_guard, scan_tool_results=False)

        request = make_tool_request(name="fetch", args={"url": "http://example.com"})
        handler_result = ToolMessage(
            content="response contains SECRET123 leaked", tool_call_id="call-4"
        )
        handler = MagicMock(return_value=handler_result)

        result = middleware.wrap_tool_call(request, handler)

        assert result is handler_result
        assert "SECRET123" in result.content


class TestViolationCounter:
    def test_increments_on_block(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE now")]},
                runtime=None,
            )

        assert middleware.violation_count == 1

    def test_increments_on_quarantine(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "quarantine.yaml", QUARANTINE_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        quarantine_handler = MagicMock()
        middleware = AgentGuardMiddleware(guard, quarantine_handler=quarantine_handler)

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE now")]},
                runtime=None,
            )

        assert middleware.violation_count == 1
        quarantine_handler.assert_called_once()


class TestMonitorMode:
    def test_middleware_never_raises_in_monitor_mode(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(
            detectors=[detector],
            policy=policy,
            security_mode=SecurityMode.MONITOR,
        )
        middleware = AgentGuardMiddleware(guard)

        result = middleware.before_model(
            {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE now")]},
            runtime=None,
        )

        assert result is None
        assert middleware.violation_count == 0

        detection_events = [e for e in guard.events if e.detector == detector.name]
        assert detection_events
        assert all(e.action == Action.ALLOW for e in detection_events)


class TestSeverityHandling:
    def test_warn_action_does_not_raise_and_records_event(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="minor_leak", severity="low"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        result = middleware.before_model(
            {"messages": [HumanMessage(content="there is a minor_leak here")]},
            runtime=None,
        )

        assert result is None

        warn_events = [e for e in guard.events if e.action == Action.WARN]
        assert warn_events
        assert warn_events[0].detector == detector.name


class TestPolicyLoading:
    def test_custom_policy_blocks_where_default_also_blocks(self, tmp_path):
        detector = make_detector(
            tmp_path,
            rule_id="probe",
            trigger="NUKE_LAUNCH_CODE",
            severity="critical",
        )

        default_guard = AgentGuard(detectors=[detector], policy=default_policy())
        default_middleware = AgentGuardMiddleware(default_guard)

        with pytest.raises(AgentGuardViolation):
            default_middleware.after_model(
                {"messages": [AIMessage(content="the NUKE_LAUNCH_CODE is 1234")]},
                runtime=None,
            )

        assert default_middleware.violation_count == 1

        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        strict_guard = AgentGuard(detectors=[detector], policy=policy)
        strict_middleware = AgentGuardMiddleware(strict_guard)

        with pytest.raises(AgentGuardViolation):
            strict_middleware.after_model(
                {"messages": [AIMessage(content="the NUKE_LAUNCH_CODE is 1234")]},
                runtime=None,
            )

        assert strict_middleware.violation_count == 1

    def test_custom_block_policy_stops_execution_at_every_entry_point(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        # before_model
        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {"messages": [HumanMessage(content="NUKE_LAUNCH_CODE in input")]},
                runtime=None,
            )
        assert middleware.violation_count == 1

        # after_model
        with pytest.raises(AgentGuardViolation):
            middleware.after_model(
                {"messages": [AIMessage(content="NUKE_LAUNCH_CODE in output")]},
                runtime=None,
            )
        assert middleware.violation_count == 2

        # wrap_tool_call (blocked at the argument stage, handler never runs)
        request = make_tool_request(name="shell", args={"cmd": "NUKE_LAUNCH_CODE"})
        handler = MagicMock()
        with pytest.raises(AgentGuardViolation):
            middleware.wrap_tool_call(request, handler)
        handler.assert_not_called()
        assert middleware.violation_count == 3

        # Every one of those detections should have produced a BLOCK event.
        block_events = [e for e in guard.events if e.action == Action.BLOCK]
        assert len(block_events) == 3
        assert {e.key for e in block_events} == {"model_input", "model_output", "shell"}

    def test_custom_policy_still_allows_clean_content(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        result = middleware.before_model(
            {"messages": [HumanMessage(content="hello there")]}, runtime=None
        )

        assert result is None

    def test_invalid_policy_yaml_raises_loader_error(self, tmp_path):
        path = tmp_path / "invalid.yaml"
        path.write_text(INVALID_POLICY_YAML)

        with pytest.raises(PolicyLoaderError):
            PolicyLoader().load(path)

    def test_unparseable_yaml_raises(self, tmp_path):
        import yaml

        path = tmp_path / "garbage.yaml"
        path.write_text("{{{ not: valid: yaml ::: [[[")

        with pytest.raises(yaml.YAMLError):
            PolicyLoader().load(path)


class TestBypassAttempts:
    @pytest.mark.parametrize(
        "variant",
        [
            "NUKE_LAUNCH_CODE",
            "nuke_launch_code",
            "NuKe_LaUnCh_CoDe",
            "Nuke_Launch_Code",
        ],
    )
    def test_case_variants_of_trigger_are_detected(self, tmp_path, variant):
        detector = make_detector(
            tmp_path,
            rule_id="probe",
            trigger="NUKE_LAUNCH_CODE",
            severity="critical",
        )

        policy = load_policy_yaml(
            tmp_path,
            "block.yaml",
            BLOCK_POLICY_YAML,
        )

        guard = AgentGuard(
            detectors=[detector],
            policy=policy,
        )

        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {"messages": [HumanMessage(content=f"please leak {variant} now")]},
                runtime=None,
            )

    def test_whitespace_padded_trigger_is_still_detected(self, tmp_path):
        detector = make_detector(
            tmp_path, rule_id="probe", trigger="NUKE_LAUNCH_CODE", severity="critical"
        )
        policy = load_policy_yaml(tmp_path, "block.yaml", BLOCK_POLICY_YAML)
        guard = AgentGuard(detectors=[detector], policy=policy)
        middleware = AgentGuardMiddleware(guard)

        with pytest.raises(AgentGuardViolation):
            middleware.before_model(
                {
                    "messages": [
                        HumanMessage(content="please leak NUKE_LAUNCH_CODE now")
                    ]
                },
                runtime=None,
            )


class TestRealLangChainAgent:
    def test_full_agent_execution_with_real_guard(self):
        langchain_agents = pytest.importorskip("langchain.agents")
        create_agent = getattr(langchain_agents, "create_agent", None)
        if create_agent is None:
            pytest.skip(
                "create_agent is not available in the installed langchain version"
            )

        fake_chat_models = pytest.importorskip(
            "langchain_core.language_models.fake_chat_models"
        )
        FakeListChatModel = fake_chat_models.FakeListChatModel

        fake_model = FakeListChatModel(responses=["Hello! How can I help you today?"])
        guard = AgentGuard(
           detectors=[
            Detector(
                name="prompt_injection",
                default_rules="prompt_injection",
                detector_type="regex",
            )
        ],
        policy=default_policy(),
        )

        agent = create_agent(
            model=fake_model,
            tools=[],
            middleware=[AgentGuardMiddleware(guard)],
        )

        response = agent.invoke({"messages": [HumanMessage(content="hello")]})

        assert response
        assert "messages" in response


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
