"""Agent implementations with tool-calling support."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.exceptions import ToolExecutionError
from devai.core.models import Message, Role, ToolCall
from devai.tools import DEFAULT_REGISTRY, ToolRegistry


class Agent:
    """General-purpose agent with optional tool-calling loop."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        config: DevAIConfig | None = None,
        *,
        system_prompt: str = "You are a helpful programming assistant.",
        tools: ToolRegistry | None = None,
        max_iterations: int = 5,
    ) -> None:
        self.client = client
        self.config = config or DevAIConfig()
        self.system_prompt = system_prompt
        self.tools = tools or DEFAULT_REGISTRY
        self.max_iterations = max_iterations
        self.history: list[Message] = []

    def run(self, prompt: str) -> str:
        """Run the agent on a user prompt, executing tools as needed."""
        self.history.append(Message(role=Role.USER, content=prompt))
        for _ in range(self.max_iterations):
            content, tool_calls = self.client.chat_with_tools(
                self.history,
                self.tools.schemas(),
                system=self.system_prompt,
            )
            if not tool_calls:
                if content:
                    self.history.append(Message(role=Role.ASSISTANT, content=content))
                return content or ""

            assistant_msg = Message(
                role=Role.ASSISTANT,
                content=content or "",
                tool_calls=tool_calls,
            )
            self.history.append(assistant_msg)

            for call in tool_calls:
                result = self._execute_tool(call)
                self.history.append(
                    Message(
                        role=Role.TOOL,
                        content=result,
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )

        return content or "Max iterations reached."

    def _execute_tool(self, call: ToolCall) -> str:
        try:
            return self.tools.execute(call.name, call.arguments)
        except Exception as exc:
            raise ToolExecutionError(f"Tool '{call.name}' failed: {exc}") from exc

    def reset(self) -> None:
        self.history.clear()


class CoderAgent(Agent):
    """Agent specialized for coding tasks with built-in dev tools."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        config: DevAIConfig | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            client,
            config,
            system_prompt=(
                "You are an expert software engineer. "
                "Write clean, tested, well-documented code. "
                "Use available tools to inspect files and analyze code."
            ),
            tools=DEFAULT_REGISTRY,
            **kwargs,
        )

    def review(self, code: str, language: str = "python") -> str:
        from devai.prompts import CODE_REVIEW

        return self.run(CODE_REVIEW.format(code=code, language=language))

    def debug(self, code: str, error: str, language: str = "python") -> str:
        from devai.prompts import DEBUG

        return self.run(DEBUG.format(code=code, error=error, language=language))
