"""Chain abstractions for composing LLM pipelines."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts.template import PromptTemplate


class Chain:
    """A simple prompt → LLM → output pipeline."""

    def __init__(
        self,
        prompt: PromptTemplate | str,
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        system_prompt: str | None = None,
    ):
        self.prompt = (
            PromptTemplate(prompt) if isinstance(prompt, str) else prompt
        )
        self.config = config or DevAIConfig()
        self.client = client or LLMClient(self.config)
        self.system_prompt = system_prompt

    async def run(self, **kwargs: Any) -> str:
        user_content = self.prompt.format(**kwargs)
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        messages.append(Message(role=Role.USER, content=user_content))
        response = await self.client.chat(messages)
        return response.content

    def run_sync(self, **kwargs: Any) -> str:
        import asyncio

        return asyncio.run(self.run(**kwargs))

    async def stream(self, **kwargs: Any) -> AsyncIterator[str]:
        """Stream the LLM response token by token."""
        user_content = self.prompt.format(**kwargs)
        messages: list[Message] = []
        if self.system_prompt:
            messages.append(Message(role=Role.SYSTEM, content=self.system_prompt))
        messages.append(Message(role=Role.USER, content=user_content))
        async for chunk in self.client.stream(messages):
            if chunk.content:
                yield chunk.content

    async def close(self) -> None:
        await self.client.close()


class SequentialChain:
    """Run multiple chains in sequence, passing output forward."""

    def __init__(self, chains: list[Chain], output_key: str = "output"):
        self.chains = chains
        self.output_key = output_key

    async def run(self, **kwargs: Any) -> dict[str, str]:
        results: dict[str, str] = {}
        current_kwargs = dict(kwargs)
        for i, chain in enumerate(self.chains):
            output = await chain.run(**current_kwargs)
            key = f"step_{i}"
            results[key] = output
            current_kwargs[self.output_key] = output
        results["final"] = results[f"step_{len(self.chains) - 1}"]
        return results

    def run_sync(self, **kwargs: Any) -> dict[str, str]:
        import asyncio

        return asyncio.run(self.run(**kwargs))

    async def close(self) -> None:
        for chain in self.chains:
            await chain.close()
