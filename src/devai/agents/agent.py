"""Base agent with tool-calling loop."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.tools.registry import ToolRegistry


class Agent:
    """General-purpose AI agent with optional tool use."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.messages: list[Message] = []

    def reset(self) -> None:
        self.messages = []

    def _system_message(self) -> Message:
        return Message(role=Role.SYSTEM, content=self.system_prompt)

    def run(self, user_input: str) -> str:
        self.messages.append(Message(role=Role.USER, content=user_input))
        all_messages = [self._system_message(), *self.messages]

        for _ in range(self.max_iterations):
            tool_list = self.tools.get_tools() if len(self.tools) > 0 else None
            response = self.client.complete(all_messages, tools=tool_list)
            self.messages.append(response)
            all_messages.append(response)

            if not response.tool_calls:
                return response.content

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                tool_msg = Message(
                    role=Role.TOOL,
                    content=result,
                    tool_call_id=tc.id,
                    name=tc.name,
                )
                self.messages.append(tool_msg)
                all_messages.append(tool_msg)

        return self.messages[-1].content

    def chat(self, user_input: str) -> str:
        return self.run(user_input)
