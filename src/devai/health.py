"""Health checks for DevAI LLM providers and runtimes."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from devai.core.client import LLMClient, LLMClientProtocol, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message


@dataclass
class HealthResult:
    """Result of a provider health check."""

    healthy: bool
    provider: str
    model: str
    latency_ms: float
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "provider": self.provider,
            "model": self.model,
            "latency_ms": round(self.latency_ms, 2),
            "message": self.message,
            "details": self.details,
        }


class HealthChecker:
    """Verify that an LLM provider is reachable and responding."""

    def __init__(
        self,
        config: DevAIConfig | None = None,
        client: LLMClientProtocol | None = None,
    ) -> None:
        if client is not None:
            self.client = client
            if isinstance(client, MockLLMClient):
                self.config = DevAIConfig(api_key="mock", model="mock-model")
            else:
                self.config = getattr(client, "config", DevAIConfig())
        elif config is not None:
            self.config = config
            self.client = LLMClient(config)
        else:
            self.config = DevAIConfig()
            self.client = LLMClient(self.config)

    def check(self, *, probe: bool = True) -> HealthResult:
        """Run a health check against the configured provider."""
        start = time.perf_counter()
        provider = self._provider_name()

        if isinstance(self.client, MockLLMClient):
            return HealthResult(
                healthy=True,
                provider=provider,
                model=self.config.model,
                latency_ms=(time.perf_counter() - start) * 1000,
                message="Mock client is always healthy",
                details={"mode": "mock"},
            )

        try:
            self.config.validate()
        except Exception as exc:
            return HealthResult(
                healthy=False,
                provider=provider,
                model=self.config.model,
                latency_ms=(time.perf_counter() - start) * 1000,
                message=str(exc),
                details={"stage": "config"},
            )

        if not probe:
            reachable, detail = self._check_endpoint()
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=reachable,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message="Endpoint reachable" if reachable else detail,
                details={"stage": "endpoint", **({"error": detail} if not reachable else {})},
            )

        try:
            response = self.client.complete(
                [Message.user("ping")],
                max_tokens=5,
                temperature=0.0,
            )
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=True,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message="Provider responded successfully",
                details={"response_preview": response[:80]},
            )
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=False,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message=str(exc),
                details={"stage": "completion"},
            )

    async def acheck(self, *, probe: bool = True) -> HealthResult:
        """Run an async health check against the configured provider."""
        start = time.perf_counter()
        provider = self._provider_name()

        if isinstance(self.client, MockLLMClient):
            return HealthResult(
                healthy=True,
                provider=provider,
                model=self.config.model,
                latency_ms=(time.perf_counter() - start) * 1000,
                message="Mock client is always healthy",
                details={"mode": "mock"},
            )

        try:
            self.config.validate()
        except Exception as exc:
            return HealthResult(
                healthy=False,
                provider=provider,
                model=self.config.model,
                latency_ms=(time.perf_counter() - start) * 1000,
                message=str(exc),
                details={"stage": "config"},
            )

        if not probe:
            reachable, detail = self._check_endpoint()
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=reachable,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message="Endpoint reachable" if reachable else detail,
                details={"stage": "endpoint", **({"error": detail} if not reachable else {})},
            )

        try:
            response = await self.client.acomplete(
                [Message.user("ping")],
                max_tokens=5,
                temperature=0.0,
            )
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=True,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message="Provider responded successfully",
                details={"response_preview": response[:80]},
            )
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            return HealthResult(
                healthy=False,
                provider=provider,
                model=self.config.model,
                latency_ms=latency,
                message=str(exc),
                details={"stage": "completion"},
            )

    def _provider_name(self) -> str:
        if isinstance(self.client, MockLLMClient):
            return "mock"
        base = self.config.base_url.lower()
        if self.config.api_key == "mock":
            return "mock"
        if "ollama" in base or "11434" in base:
            return "ollama"
        if "openai.com" in base:
            return "openai"
        return "custom"

    def _check_endpoint(self) -> tuple[bool, str]:
        url = self.config.base_url.rstrip("/") + "/models"
        headers = {"Authorization": f"Bearer {self.config.api_key}"}
        headers.update(self.config.extra_headers)
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(url, headers=headers)
                if response.status_code < 400:
                    return True, ""
                return False, f"HTTP {response.status_code}"
        except Exception as exc:
            return False, str(exc)


def check_health(
    *,
    provider: str = "openai",
    model: str | None = None,
    api_key: str | None = None,
    use_mock: bool = False,
    probe: bool = True,
    **kwargs: Any,
) -> HealthResult:
    """One-line health check for a provider."""
    if use_mock or provider.lower() == "mock":
        checker = HealthChecker(client=MockLLMClient())
    else:
        config = DevAIConfig.from_provider(provider, model=model, api_key=api_key, **kwargs)
        checker = HealthChecker(config=config)
    return checker.check(probe=probe)
