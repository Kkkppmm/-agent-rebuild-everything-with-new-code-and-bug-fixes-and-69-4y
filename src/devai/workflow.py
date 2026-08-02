"""DevWorkflow — orchestrate multiple DevAI programs for complex developer workflows."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from devai.assistant import CodeAssistant
from devai.presets import get_preset
from devai.program import DevProgram, ProgramResult

StepCallback = Callable[["WorkflowStepResult", dict[str, str]], None]
ErrorCallback = Callable[[str, Exception, dict[str, str]], None]


@dataclass
class WorkflowStep:
    """A single step in a DevWorkflow."""

    name: str
    program: DevProgram | str
    parallel_group: str | None = None

    def resolve_program(self, assistant: CodeAssistant) -> DevProgram:
        if isinstance(self.program, DevProgram):
            return self.program
        return get_preset(self.program, assistant)


@dataclass
class WorkflowStepResult:
    """Output from a single workflow step."""

    name: str
    program_name: str
    results: list[ProgramResult]
    duration_seconds: float
    parallel_group: str | None = None

    @property
    def output(self) -> str:
        """Combined markdown output for this step."""
        parts = [f"### {result.name} ({result.action})\n\n{result.output}" for result in self.results]
        return "\n\n".join(parts)


@dataclass
class WorkflowResult:
    """Complete output from a DevWorkflow run."""

    name: str
    steps: list[WorkflowStepResult]
    context: dict[str, str]
    duration_seconds: float

    def summarize(self) -> str:
        """Format all step outputs as markdown."""
        parts = [f"## {step.name}\n\n{step.output}" for step in self.steps]
        header = f"# Workflow: {self.name}\n\n"
        return header + "\n\n---\n\n".join(parts)


@dataclass
class DevWorkflow:
    """Orchestrate multiple DevAI programs with sequential and parallel execution.

    DevWorkflow lets developers compose presets and custom programs into
    larger automation pipelines. Step outputs are merged into a shared
  context so later steps can reference earlier results via ``$key`` variables.
    """

    name: str
    assistant: CodeAssistant
    steps: list[WorkflowStep] = field(default_factory=list)
    _on_step: list[StepCallback] = field(default_factory=list, init=False, repr=False)
    _on_error: list[ErrorCallback] = field(default_factory=list, init=False, repr=False)

    def add(
        self,
        name: str,
        program: DevProgram | str,
        *,
        parallel_group: str | None = None,
    ) -> DevWorkflow:
        """Add a workflow step (program object or preset name)."""
        self.steps.append(
            WorkflowStep(name=name, program=program, parallel_group=parallel_group)
        )
        return self

    def add_parallel(self, group_name: str, *steps: tuple[str, DevProgram | str]) -> DevWorkflow:
        """Add multiple steps that execute in parallel within the same group."""
        for step_name, program in steps:
            self.add(step_name, program, parallel_group=group_name)
        return self

    def on_step(self, callback: StepCallback) -> DevWorkflow:
        """Register a callback invoked after each step completes."""
        self._on_step.append(callback)
        return self

    def on_error(self, callback: ErrorCallback) -> DevWorkflow:
        """Register a callback invoked when a step fails."""
        self._on_error.append(callback)
        return self

    def _merge_results(self, context: dict[str, str], step: WorkflowStepResult) -> None:
        context[step.name] = step.output
        for result in step.results:
            context[result.name] = result.output

    def _run_step(
        self,
        step: WorkflowStep,
        context: dict[str, str],
    ) -> WorkflowStepResult:
        program = step.resolve_program(self.assistant)
        started = time.perf_counter()
        results = program.run(dict(context))
        duration = time.perf_counter() - started
        step_result = WorkflowStepResult(
            name=step.name,
            program_name=program.name,
            results=results,
            duration_seconds=duration,
            parallel_group=step.parallel_group,
        )
        self._merge_results(context, step_result)
        for callback in self._on_step:
            callback(step_result, context)
        return step_result

    def _run_parallel_group(
        self,
        group_steps: list[WorkflowStep],
        context: dict[str, str],
    ) -> list[WorkflowStepResult]:
        group_context = dict(context)
        step_results: list[WorkflowStepResult] = []

        def run_one(step: WorkflowStep) -> WorkflowStepResult:
            return self._run_step(step, dict(group_context))

        with ThreadPoolExecutor(max_workers=len(group_steps)) as executor:
            futures = {executor.submit(run_one, step): step for step in group_steps}
            for future in as_completed(futures):
                step = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    for callback in self._on_error:
                        callback(step.name, exc, context)
                    raise
                step_results.append(result)

        for result in sorted(step_results, key=lambda r: r.name):
            self._merge_results(context, result)
        return step_results

    def run(self, context: dict[str, str] | None = None) -> WorkflowResult:
        """Execute the workflow sequentially, running parallel groups concurrently."""
        ctx = dict(context or {})
        started = time.perf_counter()
        all_results: list[WorkflowStepResult] = []
        index = 0

        while index < len(self.steps):
            step = self.steps[index]
            if step.parallel_group:
                group_name = step.parallel_group
                group_steps: list[WorkflowStep] = []
                while index < len(self.steps) and self.steps[index].parallel_group == group_name:
                    group_steps.append(self.steps[index])
                    index += 1
                try:
                    all_results.extend(self._run_parallel_group(group_steps, ctx))
                except Exception:
                    raise
            else:
                try:
                    all_results.append(self._run_step(step, ctx))
                except Exception as exc:
                    for callback in self._on_error:
                        callback(step.name, exc, ctx)
                    raise
                index += 1

        duration = time.perf_counter() - started
        return WorkflowResult(
            name=self.name,
            steps=all_results,
            context=ctx,
            duration_seconds=duration,
        )

    async def _arun_step(
        self,
        step: WorkflowStep,
        context: dict[str, str],
    ) -> WorkflowStepResult:
        program = step.resolve_program(self.assistant)
        started = time.perf_counter()
        results = await program.arun(dict(context))
        duration = time.perf_counter() - started
        step_result = WorkflowStepResult(
            name=step.name,
            program_name=program.name,
            results=results,
            duration_seconds=duration,
            parallel_group=step.parallel_group,
        )
        self._merge_results(context, step_result)
        for callback in self._on_step:
            callback(step_result, context)
        return step_result

    async def arun(self, context: dict[str, str] | None = None) -> WorkflowResult:
        """Execute the workflow asynchronously."""
        ctx = dict(context or {})
        started = time.perf_counter()
        all_results: list[WorkflowStepResult] = []
        index = 0

        while index < len(self.steps):
            step = self.steps[index]
            if step.parallel_group:
                group_name = step.parallel_group
                group_steps: list[WorkflowStep] = []
                while index < len(self.steps) and self.steps[index].parallel_group == group_name:
                    group_steps.append(self.steps[index])
                    index += 1
                tasks = [self._arun_step(s, dict(ctx)) for s in group_steps]
                try:
                    group_results = await asyncio.gather(*tasks)
                except Exception as exc:
                    for callback in self._on_error:
                        callback(group_name, exc, ctx)
                    raise
                for result in group_results:
                    self._merge_results(ctx, result)
                all_results.extend(group_results)
            else:
                try:
                    all_results.append(await self._arun_step(step, ctx))
                except Exception as exc:
                    for callback in self._on_error:
                        callback(step.name, exc, ctx)
                    raise
                index += 1

        duration = time.perf_counter() - started
        return WorkflowResult(
            name=self.name,
            steps=all_results,
            context=ctx,
            duration_seconds=duration,
        )

    @classmethod
    def from_presets(
        cls,
        name: str,
        assistant: CodeAssistant,
        *preset_names: str,
    ) -> DevWorkflow:
        """Build a sequential workflow from preset names."""
        workflow = cls(name=name, assistant=assistant)
        for preset_name in preset_names:
            workflow.add(preset_name, preset_name)
        return workflow
