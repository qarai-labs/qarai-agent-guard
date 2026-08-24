from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
)
from langgraph.prebuilt.tool_node import ToolCallRequest
from qarai_agent_guard import Action, AgentGuard
from qarai_agent_guard.core.schemas.events import Severity, SourceClass

from qarai_agent_guard_langchain.exceptions import AgentGuardViolation


class AgentGuardMiddleware(AgentMiddleware):
    """
    LangChain middleware adapter for qarai-agent-guard.

    The middleware does not make security decisions.
    AgentGuard policy decides the action.

    Supported actions:

        ALLOW:
            Continue execution.

        WARN:
            Emit event and continue.

        REDACT:
            Apply redaction and continue.

        BLOCK:
            Stop execution.

        QUARANTINE:
            Send content to quarantine handler and stop execution.
    """

    def __init__(
        self,
        guard: AgentGuard,
        *,
        scan_input: bool = True,
        scan_output: bool = True,
        scan_tool_calls: bool = True,
        scan_tool_results: bool = True,
        quarantine_handler: Callable | None = None,
    ) -> None:
        if not isinstance(guard, AgentGuard):
            raise TypeError("guard must be an AgentGuard instance")

        self.guard = guard

        self.scan_input = scan_input
        self.scan_output = scan_output
        self.scan_tool_calls = scan_tool_calls
        self.scan_tool_results = scan_tool_results

        self.quarantine_handler = quarantine_handler

        self._violations = 0

    @property
    def name(self) -> str:
        return "AgentGuardMiddleware"

    @property
    def violation_count(self) -> int:
        return self._violations

    def _extract_content(
        self,
        message: BaseMessage,
    ) -> str:
        if isinstance(message.content, str):
            return message.content

        return str(message.content)

    def _enforce_decision(
        self,
        *,
        decision,
        content: Any,
        detections=None,
        source: str,
    ) -> Any:
        """
        Execute policy decision.

        This is the only place where actions are enforced.
        """

        action = decision.action

        if action == Action.ALLOW:
            return content

        if action == Action.WARN:
            self.guard._emit_event(
                detector="middleware",
                severity=Severity.MEDIUM,
                action=Action.WARN,
                key=source,
                message=decision.reason,
                operation="middleware",
                source_class=SourceClass.UNKNOWN,
                metadata={
                    "source": source,
                    "reason": decision.reason,
                },
            )

            return content

        if action == Action.REDACT:
            if not detections:
                return content

            return self.guard.apply_redactions(
                content,
                detections=detections,
            )

        if action == Action.BLOCK:
            self._violations += 1

            raise AgentGuardViolation(
                f"""
AgentGuard blocked execution.

Source:
{source}

Reason:
{decision.reason}
"""
            )

        if action == Action.QUARANTINE:
            self._violations += 1

            if self.quarantine_handler:
                self.quarantine_handler(
                    source=source,
                    content=content,
                    decision=decision,
                )

            raise AgentGuardViolation(
                f"""
Content quarantined by AgentGuard.

Source:
{source}

Reason:
{decision.reason}
"""
            )

        return content

    def before_model(
        self,
        state: Any,
        runtime: Any,
    ) -> dict[str, Any] | None:
        if not self.scan_input:
            return None

        messages = (
            state.get("messages", [])
            if isinstance(state, dict)
            else getattr(state, "messages", [])
        )

        for message in messages:
            content = self._extract_content(message)

            if not content:
                continue

            decision, detections = self.guard.check(
                key="model_input",
                value=content,
                operation="input",
            )

            new_content = self._enforce_decision(
                decision=decision,
                content=content,
                detections=detections,
                source="model_input",
            )

            if new_content != content:
                message.content = new_content

        return None

    async def abefore_model(
        self,
        state,
        runtime,
    ):
        return self.before_model(state, runtime)

    def after_model(
        self,
        state,
        runtime,
    ):
        if not self.scan_output:
            return None

        messages = (
            state.get("messages", [])
            if isinstance(state, dict)
            else getattr(state, "messages", [])
        )

        if not messages:
            return None

        message = messages[-1]

        if not isinstance(
            message,
            AIMessage,
        ):
            return None

        content = self._extract_content(message)

        decision, detections = self.guard.check(
            key="model_output",
            value=content,
            operation="output",
        )

        new_content = self._enforce_decision(
            decision=decision,
            content=content,
            detections=detections,
            source="model_output",
        )

        if new_content != content:
            return {"messages": [AIMessage(content=new_content)]}

        return None

    async def aafter_model(
        self,
        state,
        runtime,
    ):
        return self.after_model(state, runtime)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            ToolMessage,
        ],
    ) -> ToolMessage:
        tool_name = request.tool_call.get(
            "name",
            "unknown",
        )

        if self.scan_tool_calls:
            arguments = request.tool_call.get(
                "args",
                {},
            )

            decision, detections = self.guard.check(
                key=tool_name,
                value=arguments,
                operation="tool_call",
            )

            new_arguments = self._enforce_decision(
                decision=decision,
                content=arguments,
                detections=detections,
                source=f"tool_call:{tool_name}",
            )

            if new_arguments != arguments:
                request.tool_call["args"] = new_arguments

        result = handler(request)

        if not self.scan_tool_results:
            return result

        content = (
            result.content
            if isinstance(
                result.content,
                str,
            )
            else str(result.content)
        )

        decision, detections = self.guard.check(
            key="tool_output",
            value=content,
            operation="tool_result",
        )

        new_content = self._enforce_decision(
            decision=decision,
            content=content,
            detections=detections,
            source=f"tool_output:{tool_name}",
        )

        if new_content != content:
            return ToolMessage(
                content=new_content,
                tool_call_id=result.tool_call_id,
            )

        return result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            Awaitable[ToolMessage],
        ],
    ) -> ToolMessage:
        tool_name = request.tool_call.get(
            "name",
            "unknown",
        )

        if self.scan_tool_calls:
            arguments = request.tool_call.get(
                "args",
                {},
            )

            decision, detections = self.guard.check(
                key=tool_name,
                value=arguments,
                operation="tool_call",
            )

            self._enforce_decision(
                decision=decision,
                content=arguments,
                detections=detections,
                source=f"tool_call:{tool_name}",
            )

        result = await handler(request)

        if not self.scan_tool_results:
            return result

        content = (
            result.content
            if isinstance(
                result.content,
                str,
            )
            else str(result.content)
        )

        decision, detections = self.guard.check(
            key="tool_output",
            value=content,
            operation="tool_result",
        )

        new_content = self._enforce_decision(
            decision=decision,
            content=content,
            detections=detections,
            source=f"tool_output:{tool_name}",
        )

        if new_content != content:
            return ToolMessage(
                content=new_content,
                tool_call_id=result.tool_call_id,
            )

        return result
