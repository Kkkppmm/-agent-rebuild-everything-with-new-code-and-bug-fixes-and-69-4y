"""Batch and concurrent LLM request utilities."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import LLMResponse


@dataclass
class BatchRequest:
    """A single item in a batch completion."""

    prompt: str
    system: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class BatchResult:
    """Result of a batch completion."""

    prompt: str
    response: LLMResponse
    metadata: dict[str, Any] | None = None
    error: str | None = None

    @property
    def content(self) -> str:
        return self.response.content if self.response else ""


class BatchRunner:
    """Run multiple LLM completions concurrently."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        *,
        max_concurrency: int = 5,
    ) -> None:
        self.client = client
        self.max_concurrency = max_concurrency

    def run(self, requests: list[BatchRequest]) -> list[BatchResult]:
        return asyncio.run(self.arun(requests))

    async def arun(self, requests: list[BatchRequest]) -> list[BatchResult]:
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _process(req: BatchRequest) -> BatchResult:
            async with semaphore:
                try:
                    response = await self.client.acomplete(req.prompt, system=req.system)
                    return BatchResult(
                        prompt=req.prompt,
                        response=response,
                        metadata=req.metadata,
                    )
                except Exception as e:
                    return BatchResult(
                        prompt=req.prompt,
                        response=LLMResponse(content="", model="error"),
                        metadata=req.metadata,
                        error=str(e),
                    )

        return list(await asyncio.gather(*[_process(r) for r in requests]))

    def run_prompts(self, prompts: list[str]) -> list[str]:
        """Convenience method: run a list of prompt strings and return contents."""
        requests = [BatchRequest(prompt=p) for p in prompts]
        results = self.run(requests)
        return [r.content for r in results]
