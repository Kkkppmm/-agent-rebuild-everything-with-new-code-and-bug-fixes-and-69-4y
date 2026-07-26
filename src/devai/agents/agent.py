"""Base agent with tool-calling loop."""

from __future__ import annotations

from typing import Any, Protocol

from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


class LLMProtocol(Protocol):
    def chat(
        self,
        messages: list[Message],
        *,
        tools: list | None = None,
        **kwargs: Any,
    ) -> Message: ...


class Agent:
    """An AI agent that can use tools in a loop until it produces a final answer."""

    def __init__(
        self,
        llm: LLMProtocol,
        tools: ToolRegistry | None = None,
        *,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ) -> None:
        self.llm = llm
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations

    def run(self, task: str, *, context: list[Message] | None = None) -> str:
        """Execute a task, using tools as needed."""
        messages: list[Message] = [Message(role=Role.SYSTEM, content=self.system_prompt)]
        if context:
            messages.extend(context)
        messages.append(Message(role=Role.USER, content=task))

        tool_list = self.tools.list_tools() if len(self.tools) > 0 else None

        for _ in range(self.max_iterations):
            response = self.llm.chat(messages, tools=tool_list)
            messages.append(response)

            if not response.tool_calls:
                return response.content

            for tc in response.tool_calls:
                result = self._execute_tool(tc)
                messages.append(
                    Message(
                        role=Role.TOOL,
                        content=result,
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

        return messages[-1].content if messages else ""

    def _execute_tool(self, tool_call: ToolCall) -> str:
        return self.tools.execute(tool_call.name, tool_call.arguments)
