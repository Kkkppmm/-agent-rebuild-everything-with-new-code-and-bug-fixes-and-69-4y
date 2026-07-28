"""DevApp — build and ship AI-powered developer tools from programs."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.program import DevProgram, ProgramResult
from devai.runtime import DevRuntime


@dataclass
class DevApp:
    """Lightweight application runner for DevAI programs.

    DevApp wraps DevRuntime so developers can ship CLI tools, scripts,
    and automation programs with minimal boilerplate.
    """

    name: str
    runtime: DevRuntime
    default_program: str | None = None
    default_context: dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        name: str = "devapp",
        *,
        provider: str = "openai",
        model: str | None = None,
        api_key: str | None = None,
        project_path: str | Path | None = None,
        use_mock: bool = False,
        default_program: str | None = None,
        **kwargs: Any,
    ) -> DevApp:
        """Bootstrap an application with sensible defaults."""
        runtime = DevRuntime.create(
            provider=provider,
            model=model,
            api_key=api_key,
            project_path=project_path,
            use_mock=use_mock,
            **kwargs,
        )
        return cls(
            name=name,
            runtime=runtime,
            default_program=default_program,
        )

    @classmethod
    def from_runtime(
        cls,
        runtime: DevRuntime,
        *,
        name: str = "devapp",
        default_program: str | None = None,
    ) -> DevApp:
        """Wrap an existing DevRuntime as an application."""
        return cls(name=name, runtime=runtime, default_program=default_program)

    def with_context(self, **context: str) -> DevApp:
        """Set default context values for subsequent runs."""
        self.default_context.update(context)
        return self

    def use_preset(self, name: str) -> DevApp:
        """Set the default program to a built-in preset."""
        self.runtime.preset(name)
        self.default_program = name
        return self

    def load(self, path: str | Path) -> DevProgram:
        """Load a program file and set it as the default."""
        program = self.runtime.load_program(path)
        self.default_program = program.name
        return program

    def run(
        self,
        program: DevProgram | str | None = None,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a program with merged default and per-call context."""
        merged = {**self.default_context, **(context or {})}
        target = program or self.default_program
        if target is None:
            raise ValueError("No program specified. Call use_preset(), load(), or pass a program.")
        return self.runtime.run(target, merged)

    def summarize(self, results: list[ProgramResult]) -> str:
        """Format program results as markdown."""
        return self.runtime.summarize(results)

    def run_and_print(
        self,
        program: DevProgram | str | None = None,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a program and print a markdown summary."""
        results = self.run(program, context)
        print(self.summarize(results))
        return results

    async def arun(
        self,
        program: DevProgram | str | None = None,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a program asynchronously with merged default and per-call context."""
        merged = {**self.default_context, **(context or {})}
        target = program or self.default_program
        if target is None:
            raise ValueError("No program specified. Call use_preset(), load(), or pass a program.")
        return await self.runtime.arun(target, merged)

    def dry_run(
        self,
        program: DevProgram | str | None = None,
        context: dict[str, str] | None = None,
    ) -> list:
        """Preview program steps without calling the LLM."""
        merged = {**self.default_context, **(context or {})}
        target = program or self.default_program
        if target is None:
            raise ValueError("No program specified. Call use_preset(), load(), or pass a program.")
        return self.runtime.dry_run(target, merged)

    def build_cli_parser(self) -> argparse.ArgumentParser:
        """Build an argparse parser for this application."""
        parser = argparse.ArgumentParser(
            prog=self.name,
            description=f"{self.name} — powered by DevAI",
        )
        parser.add_argument(
            "--program",
            "-p",
            help="Program preset name or JSON/YAML file path",
            default=self.default_program,
        )
        parser.add_argument(
            "--code",
            "-c",
            help="Code input or file path",
        )
        parser.add_argument(
            "--diff",
            help="Diff input or file path",
        )
        parser.add_argument(
            "--mock",
            action="store_true",
            help="Use mock LLM (no API key required)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview program steps without calling the LLM",
        )
        parser.add_argument(
            "--context",
            action="append",
            metavar="KEY=VALUE",
            help="Additional context values",
        )
        return parser

    def cli(self, argv: list[str] | None = None) -> int:
        """Run this application as a CLI tool."""
        parser = self.build_cli_parser()
        args = parser.parse_args(argv)

        if args.mock:
            self.runtime = DevRuntime.create(use_mock=True)
            self.default_context = {}

        context: dict[str, str] = dict(self.default_context)
        if args.code:
            context["code"] = _read_input(args.code)
        if args.diff:
            context["diff"] = _read_input(args.diff)
        if args.context:
            for item in args.context:
                if "=" not in item:
                    parser.error(f"Invalid context value: {item!r} (expected KEY=VALUE)")
                key, value = item.split("=", 1)
                context[key] = value

        program_name = args.program or self.default_program
        if program_name is None:
            parser.error("No program specified. Use --program or set a default.")

        if args.dry_run:
            program = self._resolve_program(program_name)
            plan = program.dry_run(context)
            for step in plan:
                preview = step.input_preview[:80]
                if len(step.input_preview) > 80:
                    preview += "..."
                print(f"  {step.index}. {step.name} ({step.action})")
                print(f"     input[{step.input_key}]: {preview!r}")
                if step.kwargs:
                    print(f"     kwargs: {step.kwargs}")
            return 0

        results = self.run(program_name, context)
        print(self.summarize(results))
        return 0

    def _resolve_program(self, program: str) -> DevProgram:
        path = Path(program)
        if path.exists() and path.is_file():
            return self.runtime.load_program(path)
        if program in self.runtime._programs:
            return self.runtime._programs[program]
        return self.runtime.preset(program)


def _read_input(path_or_text: str) -> str:
    path = Path(path_or_text)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return path_or_text


def main() -> None:
    """Entry point for a default DevApp CLI."""
    app = DevApp.create(name="devai-app", use_mock=True, default_program="pre-commit")
    sys.exit(app.cli())
