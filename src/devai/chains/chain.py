"""Base chain for composing LLM calls."""

from typing import Any, Optional, Protocol

from devai.core.models import Message, Role
from devai.prompts.template import PromptTemplate


class LLMProtocol(Protocol):
    def complete(self, messages: list[Message], **kwargs: Any) -> Message: ...


class Chain:
    """A single-step LLM chain: template → prompt → response."""

    def __init__(
        self,
        client: LLMProtocol,
        template: PromptTemplate | str,
        system_prompt: str = "",
    ) -> None:
        self.client = client
        if isinstance(template, str):
            self.template = PromptTemplate(template)
        else:
            self.template = template
        self.system_prompt = system_prompt

    def run(self, **kwargs: Any) -> str:
        prompt = self.template.format(**kwargs)
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        messages.append(Message(role=Role.USER, content=prompt))
        response = self.client.complete(messages)
        return response.content
