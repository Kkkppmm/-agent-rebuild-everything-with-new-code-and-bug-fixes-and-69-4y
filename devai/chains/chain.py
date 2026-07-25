"""Simple prompt → LLM pipeline."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts.template import PromptTemplate


class Chain:
    """A chain that formats a prompt template and sends it to an LLM."""

    def __init__(
        self,
        prompt: PromptTemplate,
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.prompt = prompt
        self.config = config or DevAIConfig()
        self.client = client or LLMClient(self.config)
        self.system_prompt = system_prompt

    def run(self, **variables: Any) -> str:
        """Format the prompt and return the LLM response text."""
        user_content = self.prompt.format(**variables)
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message.system(self.system_prompt))
        messages.append(Message.user(user_content))
        response = self.client.chat(messages)
        return response.content or ""

    async def arun(self, **variables: Any) -> str:
        """Async version of run."""
        user_content = self.prompt.format(**variables)
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message.system(self.system_prompt))
        messages.append(Message.user(user_content))
        response = await self.client.achat(messages)
        return response.content or ""

    def __or__(self, other: Chain) -> Chain:
        """Compose two chains (sequential — second uses first output as 'input')."""
        first = self

        class ComposedChain(Chain):
            def run(self, **variables: Any) -> str:
                first_output = first.run(**variables)
                return other.run(input=first_output)

            async def arun(self, **variables: Any) -> str:
                first_output = await first.arun(**variables)
                return await other.arun(input=first_output)

        return ComposedChain(prompt=other.prompt, client=other.client, config=other.config)
