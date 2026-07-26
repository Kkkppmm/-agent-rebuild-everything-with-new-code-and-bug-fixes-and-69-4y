"""Simple single-prompt chain."""

from __future__ import annotations

from dataclasses import dataclass

from devai.core.client import LLMClient
from devai.core.messages import Message
from devai.prompts.template import PromptTemplate


@dataclass
class SimpleChain:
    """A chain that formats a prompt template and calls the LLM."""

    client: LLMClient
    prompt: PromptTemplate
    system_message: str | None = None

    def run(self, **kwargs: str) -> str:
        messages: list[Message] = []
        if self.system_message:
            messages.append(Message.system(self.system_message))
        messages.append(Message.user(self.prompt.format(**kwargs)))
        response = self.client.complete(messages)
        return response.content

    async def arun(self, **kwargs: str) -> str:
        messages: list[Message] = []
        if self.system_message:
            messages.append(Message.system(self.system_message))
        messages.append(Message.user(self.prompt.format(**kwargs)))
        response = await self.client.acomplete(messages)
        return response.content
