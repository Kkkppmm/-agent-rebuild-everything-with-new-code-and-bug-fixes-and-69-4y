"""Base agent with tool-calling loop."""

from __future__ import annotations

from typing import Any, Protocol

from devai.core.models import Message, Role
from devai.tools.registry import ToolRegistry


class LLMProtocol(Protocol):
    def complete(
        self,
        messages: list[Message],
        *,
        tools: list | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> Message: ...


class Agent:
    """General-purpose agent with tool execution loop."""

    def __init__(
        self,
        llm: LLMProtocol,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ) -> None:
        self.llm = llm
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.messages: list[Message] = []

    def reset(self) -> None:
        self.messages.clear()

    def run(self, user_input: str) -> str:
        """Execute the agent loop and return the final response."""
        if not self.messages:
            self.messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        self.messages.append(Message(role=Role.USER, content=user_input))

        for _ in range(self.max_iterations):
            tool_schemas = self.tools.get_schemas() if len(self.tools) > 0 else None
            response = self.llm.complete(self.messages, tools=tool_schemas)
            self.messages.append(response)

            if not response.tool_calls:
                return response.content

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                self.messages.append(
                    Message(
                        role=Role.TOOL,
                        content=result,
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

        return self.messages[-1].content
