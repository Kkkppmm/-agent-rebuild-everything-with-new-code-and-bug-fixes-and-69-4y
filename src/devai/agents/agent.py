"""Base agent with tool-calling loop."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role, ToolCall
from devai.core.exceptions import AgentError
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


class Agent:
    """An AI agent that can use tools to accomplish tasks."""

    def __init__(
        self,
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
        memory: ConversationMemory | None = None,
    ):
        self.config = config or DevAIConfig()
        self.client = client or LLMClient(self.config)
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.memory = memory or ConversationMemory()

    async def run(self, task: str) -> str:
        """Execute a task using the tool-calling loop."""
        self.memory.add(Role.USER, task)
        messages = self._build_messages()

        for _ in range(self.max_iterations):
            response = await self.client.chat(
                messages,
                tools=self.tools.get_tools() if len(self.tools) > 0 else None,
            )

            if response.tool_calls:
                self.memory.add(
                    Role.ASSISTANT,
                    response.content or "",
                    tool_calls=response.tool_calls,
                )
                for tc in response.tool_calls:
                    result = await self.tools.execute(tc.name, tc.arguments)
                    self.memory.add_tool_result(tc.id, result)
                messages = self._build_messages()
                continue

            self.memory.add(Role.ASSISTANT, response.content)
            return response.content

        raise AgentError(f"Agent exceeded max iterations ({self.max_iterations})")

    def run_sync(self, task: str) -> str:
        import asyncio

        return asyncio.run(self.run(task))

    def _build_messages(self) -> list[Message]:
        messages = [Message(role=Role.SYSTEM, content=self.system_prompt)]
        messages.extend(self.memory.get_messages())
        return messages

    async def close(self) -> None:
        await self.client.close()
