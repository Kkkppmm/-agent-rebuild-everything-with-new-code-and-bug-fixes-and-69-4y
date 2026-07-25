"""Chain with structured Pydantic output."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from devai.chains.chain import Chain
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.output.parsers import parse_model
from devai.prompts.template import PromptTemplate

T = TypeVar("T", bound=BaseModel)


class StructuredChain(Chain):
    """A chain that parses LLM output into a Pydantic model."""

    def __init__(
        self,
        prompt: PromptTemplate | str,
        output_model: type[T],
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        system_prompt: str | None = None,
    ):
        super().__init__(prompt, client=client, config=config, system_prompt=system_prompt)
        self.output_model = output_model

    async def run(self, **kwargs: Any) -> T:
        content = await super().run(**kwargs)
        return parse_model(content, self.output_model)

    def run_sync(self, **kwargs: Any) -> T:
        import asyncio

        return asyncio.run(self.run(**kwargs))
