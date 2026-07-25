"""Agent that runs an LLM + tool-calling loop."""

from __future__ import annotations

import json
from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


class Agent:
    """An autonomous agent that can call registered tools in a loop."""

    def __init__(
        self,
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        tools: ToolRegistry | None = None,
        system_prompt: str | None = None,
        memory: ConversationMemory | None = None,
    ) -> None:
        self.config = config or DevAIConfig()
        self.client = client or LLMClient(self.config)
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt or (
            "You are a helpful AI assistant for software developers. "
            "Use available tools when they help answer the user's question."
        )
        self.memory = memory or ConversationMemory()

    def _build_messages(self, user_input: str) -> list[Message]:
        messages: list[Message] = [Message.system(self.system_prompt)]
        messages.extend(self.memory.get_messages())
        messages.append(Message.user(user_input))
        return messages

    def _execute_tool_calls(self, response: Message) -> list[Message]:
        results: list[Message] = []
        if not response.tool_calls:
            return results
        for tc in response.tool_calls:
            try:
                output = self.tools.execute(tc.name, tc.arguments)
            except Exception as exc:
                output = json.dumps({"error": str(exc)})
            results.append(Message.tool(content=output, tool_call_id=tc.id, name=tc.name))
        return results

    def run(self, user_input: str, **kwargs: Any) -> str:
        """Run the agent synchronously until a final text response."""
        messages = self._build_messages(user_input)
        tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None

        for _ in range(self.config.max_tool_rounds):
            response = self.client.chat(messages, tools=tool_defs, **kwargs)
            messages.append(response)

            if response.tool_calls:
                messages.extend(self._execute_tool_calls(response))
                continue

            content = response.content or ""
            self.memory.add(Message.user(user_input))
            self.memory.add(Message.assistant(content))
            return content

        raise RuntimeError(f"Agent exceeded max tool rounds ({self.config.max_tool_rounds})")

    async def arun(self, user_input: str, **kwargs: Any) -> str:
        """Run the agent asynchronously until a final text response."""
        messages = self._build_messages(user_input)
        tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None

        for _ in range(self.config.max_tool_rounds):
            response = await self.client.achat(messages, tools=tool_defs, **kwargs)
            messages.append(response)

            if response.tool_calls:
                messages.extend(self._execute_tool_calls(response))
                continue

            content = response.content or ""
            self.memory.add(Message.user(user_input))
            self.memory.add(Message.assistant(content))
            return content

        raise RuntimeError(f"Agent exceeded max tool rounds ({self.config.max_tool_rounds})")

    def reset(self) -> None:
        """Clear conversation memory."""
        self.memory.clear()
