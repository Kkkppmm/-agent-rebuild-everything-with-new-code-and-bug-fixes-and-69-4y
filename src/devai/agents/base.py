"""Agent implementations for DevAI."""

from __future__ import annotations

import json
from typing import Any

from devai.core.client import LLMClientProtocol
from devai.core.exceptions import AgentError
from devai.core.models import Message
from devai.memory import ConversationMemory
from devai.tools.registry import ToolRegistry


class Agent:
    """Base agent with tool-calling loop."""

    def __init__(
        self,
        client: LLMClientProtocol,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant.",
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.memory = ConversationMemory(system_message=system_prompt)

    def run(self, task: str) -> str:
        self.memory.add_user(task)

        for _ in range(self.max_iterations):
            messages = self.memory.get_messages()
            tool_list = self.tools.get_tools() if len(self.tools) > 0 else None

            if tool_list and hasattr(self.client, "complete_with_tools"):
                content, tool_calls = self.client.complete_with_tools(messages, tool_list)
            else:
                content = self.client.complete(messages, tools=tool_list)
                tool_calls = self._parse_tool_calls(content)

            if not tool_calls:
                self.memory.add_assistant(content)
                return content

            self.memory.add(Message.assistant(content, tool_calls=tool_calls))

            for call in tool_calls:
                func = call.get("function", {})
                name = func.get("name", "")
                args_str = func.get("arguments", "{}")
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
                result = self.tools.execute(name, args)
                self.memory.add(
                    Message(
                        role="tool",
                        content=result,
                        tool_call_id=call.get("id", ""),
                        name=name,
                    )
                )

        raise AgentError(f"Agent exceeded max iterations ({self.max_iterations})")

    def _parse_tool_calls(self, content: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(content)
            if "tool_calls" in data:
                return data["tool_calls"]
        except (json.JSONDecodeError, TypeError):
            pass
        return []


class CoderAgent(Agent):
    """Agent specialized for coding tasks."""

    DEFAULT_SYSTEM = (
        "You are an expert software engineer. You have access to tools for reading files, "
        "searching code, running lint checks, and analyzing complexity. "
        "Use tools when needed to gather information before answering."
    )

    def __init__(
        self,
        client: LLMClientProtocol,
        tools: ToolRegistry | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            client=client,
            tools=tools,
            system_prompt=self.DEFAULT_SYSTEM,
            max_iterations=max_iterations,
        )
