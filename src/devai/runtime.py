"""DevRuntime — unified bootstrap for DevAI programs and developer workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, LLMClientProtocol, MockLLMClient
from devai.core.config import DevAIConfig
from devai.kit import DevKit
from devai.program import DevProgram, ProgramResult
from devai.workflow import DevWorkflow, WorkflowResult


@dataclass
class DevRuntime:
    """Single entry point for bootstrapping DevAI for developers and programs.

    DevRuntime wires together configuration, the LLM client, CodeAssistant,
    DevKit, and DevProgram so you can start building AI-powered dev tools
  in a few lines.
    """

    config: DevAIConfig
    client: LLMClientProtocol
    assistant: CodeAssistant
    kit: DevKit
    project_path: str | Path | None = None
    _programs: dict[str, DevProgram] = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def create(
        cls,
        *,
        provider: str = "openai",
        model: str | None = None,
        api_key: str | None = None,
        project_path: str | Path | None = None,
        use_mock: bool = False,
        **kwargs: Any,
    ) -> DevRuntime:
        """Bootstrap a runtime from a provider name or environment variables."""
        if use_mock or provider.lower() == "mock":
            client: LLMClientProtocol = MockLLMClient()
            config = DevAIConfig(api_key="mock", model=model or "mock-model")
        else:
            config = DevAIConfig.from_provider(
                provider, model=model, api_key=api_key, **kwargs
            )
            client = LLMClient(config)

        assistant = CodeAssistant(client=client)
        kit = DevKit(assistant=assistant, project_path=project_path)
        return cls(
            config=config,
            client=client,
            assistant=assistant,
            kit=kit,
            project_path=project_path,
        )

    @classmethod
    def from_config(
        cls,
        config: DevAIConfig,
        *,
        project_path: str | Path | None = None,
        client: LLMClientProtocol | None = None,
    ) -> DevRuntime:
        """Create a runtime from an existing DevAIConfig."""
        if client is None:
            if config.api_key == "mock":
                client = MockLLMClient()
            else:
                client = LLMClient(config)
        assistant = CodeAssistant(client=client)
        kit = DevKit(assistant=assistant, project_path=project_path)
        return cls(
            config=config,
            client=client,
            assistant=assistant,
            kit=kit,
            project_path=project_path,
        )

    def program(self, name: str = "program") -> DevProgram:
        """Create or retrieve a named DevProgram."""
        if name not in self._programs:
            self._programs[name] = DevProgram(name, self.assistant)
        return self._programs[name]

    def load_program(self, path: str | Path) -> DevProgram:
        """Load a program from a JSON or YAML file and register it."""
        program = DevProgram.from_file(path, self.assistant)
        self._programs[program.name] = program
        return program

    def preset(self, name: str) -> DevProgram:
        """Load a built-in program preset."""
        program = self.kit.preset(name)
        self._programs[program.name] = program
        return program

    def run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a program by object, registered name, preset name, or file path."""
        if isinstance(program, DevProgram):
            return program.run(context or {})
        path = Path(program)
        if path.exists() and path.is_file():
            return self.load_program(path).run(context or {})
        if program in self._programs:
            return self._programs[program].run(context or {})
        return self.preset(program).run(context or {})

    async def arun(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a program asynchronously."""
        if isinstance(program, DevProgram):
            return await program.arun(context or {})
        path = Path(program)
        if path.exists() and path.is_file():
            return await self.load_program(path).arun(context or {})
        if program in self._programs:
            return await self._programs[program].arun(context or {})
        return await self.preset(program).arun(context or {})

    def dry_run(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list:
        """Preview program steps without calling the LLM."""
        if isinstance(program, DevProgram):
            return program.dry_run(context or {})
        path = Path(program)
        if path.exists() and path.is_file():
            return self.load_program(path).dry_run(context or {})
        if program in self._programs:
            return self._programs[program].dry_run(context or {})
        return self.preset(program).dry_run(context or {})

    def summarize(self, results: list[ProgramResult]) -> str:
        """Format program results as markdown."""
        return self.kit.summarize(results)

    def review(self, code: str) -> str:
        """Quick code review."""
        return self.assistant.review(code)

    def explain(self, code: str) -> str:
        """Quick code explanation."""
        return self.assistant.explain(code)

    def generate(self, spec: str) -> str:
        """Generate code from a specification."""
        return self.assistant.generate(spec)

    def workflow(self, name: str = "workflow") -> DevWorkflow:
        """Create a new DevWorkflow bound to this runtime's assistant."""
        return DevWorkflow(name=name, assistant=self.assistant)

    def run_workflow(
        self,
        workflow: DevWorkflow,
        context: dict[str, str] | None = None,
    ) -> WorkflowResult:
        """Run a DevWorkflow and return structured results."""
        return workflow.run(context or {})

    async def arun_workflow(
        self,
        workflow: DevWorkflow,
        context: dict[str, str] | None = None,
    ) -> WorkflowResult:
        """Run a DevWorkflow asynchronously."""
        return await workflow.arun(context or {})

    def schedule(self) -> "DevSchedule":
        """Create a DevSchedule bound to this runtime."""
        from devai.schedule import DevSchedule

        return DevSchedule(runtime=self)

    def resilient_client(
        self,
        *,
        requests_per_minute: float = 60.0,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        collect_metrics: bool = True,
    ) -> Any:
        """Wrap the current client with rate limiting, circuit breaker, and metrics."""
        from devai.core.circuit_breaker import CircuitBreaker, CircuitBreakerLLMClient
        from devai.core.metrics import MetricsCollector, MetricsLLMClient
        from devai.core.rate_limit import RateLimitedLLMClient, RateLimiter

        client: Any = self.client
        client = RateLimitedLLMClient(
            client, RateLimiter(requests_per_minute=requests_per_minute)
        )
        client = CircuitBreakerLLMClient(
            client,
            CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            ),
        )
        if collect_metrics:
            client = MetricsLLMClient(client)
        return client
