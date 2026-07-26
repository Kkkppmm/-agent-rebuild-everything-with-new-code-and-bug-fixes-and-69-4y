"""Base agent with tool-calling loop."""

from typing import Any, Optional, Protocol

from devai.core.models import Message, Role, ToolCall
from devai.tools.registry import ToolRegistry


class LLMProtocol(Protocol):
    def complete(
        self,
        messages: list[Message],
        tools: Optional[list] = None,
        **kwargs: Any,
    ) -> Message: ...


class Agent:
    """An AI agent that can use tools in a multi-turn loop."""

    def __init__(
        self,
        client: LLMProtocol,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        tools: Optional[ToolRegistry] = None,
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.system_prompt = system_prompt
        self.tools = tools or ToolRegistry()
        self.max_iterations = max_iterations
        self.history: list[Message] = []

    def _system_message(self) -> Message:
        return Message(role=Role.SYSTEM, content=self.system_prompt)

    def run(self, user_input: str, **kwargs: Any) -> str:
        self.history.append(Message(role=Role.USER, content=user_input))

        tool_list = self.tools.get_tools() if len(self.tools) > 0 else None

        for _ in range(self.max_iterations):
            messages = [self._system_message()] + self.history
            response = self.client.complete(
                messages,
                tools=tool_list,
                **kwargs,
            )
            self.history.append(response)

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
                self.history.append(tool_msg)

        return self.history[-1].content

    def reset(self) -> None:
        self.history.clear()
