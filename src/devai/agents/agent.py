"""Base agent with tool-calling loop."""

from __future__ import annotations

from dataclasses import dataclass, field

from devai.core.client import LLMClient
from devai.core.exceptions import AgentError
from devai.core.messages import Message
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


@dataclass
class Agent:
    """An AI agent that can use tools in a loop."""

    client: LLMClient
    tools: ToolRegistry = field(default_factory=ToolRegistry)
    system_prompt: str = "You are a helpful AI assistant for developers."
    max_iterations: int = 10
    memory: ConversationMemory = field(default_factory=ConversationMemory)

    def run(self, task: str) -> str:
        """Execute a task using the tool-calling loop."""
        self.memory.add(Message.system(self.system_prompt))
        self.memory.add(Message.user(task))

        for _ in range(self.max_iterations):
            response = self.client.complete(
                self.memory.get_messages(),
                tools=self.tools.get_definitions() if len(self.tools) > 0 else None,
            )
            self.memory.add(response)

            if not response.tool_calls:
                return response.content

            for tool_call in response.tool_calls:
                result = self.tools.execute(tool_call.name, tool_call.arguments)
                self.memory.add(
                    Message.tool(result, tool_call_id=tool_call.id, name=tool_call.name)
                )

        raise AgentError(f"Agent exceeded max iterations ({self.max_iterations})")

    async def arun(self, task: str) -> str:
        """Async version of run."""
        self.memory.add(Message.system(self.system_prompt))
        self.memory.add(Message.user(task))

        for _ in range(self.max_iterations):
            response = await self.client.acomplete(
                self.memory.get_messages(),
                tools=self.tools.get_definitions() if len(self.tools) > 0 else None,
            )
            self.memory.add(response)

            if not response.tool_calls:
                return response.content

            for tool_call in response.tool_calls:
                result = self.tools.execute(tool_call.name, tool_call.arguments)
                self.memory.add(
                    Message.tool(result, tool_call_id=tool_call.id, name=tool_call.name)
                )

        raise AgentError(f"Agent exceeded max iterations ({self.max_iterations})")

    def reset(self) -> None:
        self.memory.clear()
