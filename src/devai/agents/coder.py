"""Agent framework with tool-calling loop."""

from __future__ import annotations

from abc import ABC, abstractmethod

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts.dev_prompts import AGENT_SYSTEM
from devai.tools.code_utils import ToolRegistry


class Agent(ABC):
    """Base agent with LLM client and optional tools."""

    def __init__(
        self,
        config: DevAIConfig | None = None,
        client: LLMClient | None = None,
        tools: ToolRegistry | None = None,
        max_iterations: int = 10,
    ) -> None:
        self.config = config or DevAIConfig.from_env()
        if client:
            self.client = client
        elif self.config.api_key == "mock-key":
            self.client = MockLLMClient(self.config)
        else:
            self.client = LLMClient(self.config)
        self.tools = tools or ToolRegistry()
        self.max_iterations = max_iterations

    @abstractmethod
    def run(self, task: str) -> str:
        """Execute the agent on a task."""


class CoderAgent(Agent):
    """Agent for coding tasks with tool-calling support."""

    def run(self, task: str) -> str:
        tool_defs = self.tools.list_tools()
        system_prompt = AGENT_SYSTEM(tools=", ".join(self.tools.names()) or "none")
        messages: list[Message] = [
            Message.system(system_prompt),
            Message.user(task),
        ]

        for _ in range(self.max_iterations):
            response = self.client.complete(messages, tools=tool_defs or None)

            if response.tool_calls:
                messages.append(response)
                for tc in response.tool_calls:
                    result = self.tools.execute(tc.name, tc.arguments)
                    messages.append(Message.tool(result, tc.id, tc.name))
                continue

            return response.content or ""

        return "Agent reached maximum iterations without completing the task."
