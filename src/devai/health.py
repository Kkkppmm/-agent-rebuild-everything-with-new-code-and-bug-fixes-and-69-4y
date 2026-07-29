"""Health checks for DevAI provider connectivity."""

from __future__ import annotations

import time
from dataclasses import dataclass

from devai.core.client import LLMClient, LLMClientProtocol, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message


@dataclass
class HealthResult:
    """Result of a provider health check."""

    healthy: bool
    provider: str
    model: str
    latency_ms: float | None = None
    message: str = ""

    def format_report(self) -> str:
        status = "healthy" if self.healthy else "unhealthy"
        lines = [
            f"Provider: {self.provider}",
            f"Model: {self.model}",
            f"Status: {status}",
        ]
        if self.latency_ms is not None:
            lines.append(f"Latency: {self.latency_ms:.1f} ms")
        if self.message:
            lines.append(f"Message: {self.message}")
        return "\n".join(lines)


class HealthChecker:
    """Check whether an LLM provider is reachable and responding."""

    def __init__(
        self,
        client: LLMClientProtocol | None = None,
        config: DevAIConfig | None = None,
    ) -> None:
        self.config = config or DevAIConfig()
        if client is not None:
            self.client = client
        elif self.config.api_key == "mock":
            self.client = MockLLMClient()
        else:
            self.client = LLMClient(self.config)

    def check(self, *, prompt: str = "ping") -> HealthResult:
        """Run a lightweight completion to verify provider connectivity."""
        provider = self._provider_name()
        start = time.perf_counter()
        try:
            response = self.client.complete(
                [Message(role="user", content=prompt)],
                max_tokens=16,
            )
            latency_ms = (time.perf_counter() - start) * 1000
            if not response:
                return HealthResult(
                    healthy=False,
                    provider=provider,
                    model=self.config.model,
                    latency_ms=latency_ms,
                    message="Provider returned an empty response",
                )
            return HealthResult(
                healthy=True,
                provider=provider,
                model=self.config.model,
                latency_ms=latency_ms,
                message="Provider responded successfully",
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=False,
                provider=provider,
                model=self.config.model,
                latency_ms=latency_ms,
                message=str(exc),
            )

    def _provider_name(self) -> str:
        if self.config.api_key == "mock":
            return "mock"
        if "ollama" in self.config.base_url or self.config.api_key == "ollama":
            return "ollama"
        if "openai" in self.config.base_url:
            return "openai"
        return "custom"


def check_health(
    *,
    client: LLMClientProtocol | None = None,
    config: DevAIConfig | None = None,
    use_mock: bool = False,
) -> HealthResult:
    """Convenience function to run a provider health check."""
    if use_mock:
        config = DevAIConfig(api_key="mock", model="mock-model")
        client = MockLLMClient()
    return HealthChecker(client=client, config=config).check()
