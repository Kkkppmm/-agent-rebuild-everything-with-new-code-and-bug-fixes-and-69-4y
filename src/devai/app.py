"""DevApp — application framework for shipping AI-powered developer tools."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.program import DevProgram, ProgramResult
from devai.runtime import DevRuntime

CommandHandler = Callable[..., str]


@dataclass
class DevCommand:
    """A user-defined command for a DevApp."""

    name: str
    help: str
    handler: CommandHandler
    requires_input: bool = False


@dataclass
class DevApp:
    """Application framework for building and shipping AI-powered CLI tools.

    DevApp wires DevRuntime, custom commands, and registered programs into
    a single deployable developer tool.
    """

    name: str
    description: str = ""
    runtime: DevRuntime | None = None
    commands: dict[str, DevCommand] = field(default_factory=dict)
    _programs: dict[str, DevProgram] = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def create(
        cls,
        name: str,
        description: str = "",
        **runtime_kwargs: Any,
    ) -> DevApp:
        """Create a DevApp with an auto-configured DevRuntime."""
        runtime = DevRuntime.create(**runtime_kwargs)
        return cls(name=name, description=description, runtime=runtime)

    def command(
        self,
        name: str,
        help: str = "",
        requires_input: bool = False,
    ) -> Callable[[CommandHandler], CommandHandler]:
        """Decorator to register a custom command handler."""

        def decorator(fn: CommandHandler) -> CommandHandler:
            self.commands[name] = DevCommand(
                name=name,
                help=help or (fn.__doc__ or "").strip(),
                handler=fn,
                requires_input=requires_input,
            )
            return fn

        return decorator

    def register_program(self, name: str, program: DevProgram) -> None:
        """Register a DevProgram under a given name."""
        self._programs[name] = program

    def register_preset(self, name: str) -> DevProgram:
        """Load and register a built-in preset program."""
        if self.runtime is None:
            raise RuntimeError("DevApp runtime is not configured")
        program = self.runtime.preset(name)
        self._programs[program.name] = program
        return program

    def run_program(self, name: str, context: dict[str, str]) -> list[ProgramResult]:
        """Run a registered program by name."""
        if name in self._programs:
            return self._programs[name].run(context)
        if self.runtime is not None:
            return self.runtime.run(name, context)
        raise ValueError(f"No program registered with name '{name}'")

    @property
    def assistant(self) -> CodeAssistant:
        if self.runtime is None:
            raise RuntimeError("DevApp runtime is not configured")
        return self.runtime.assistant

    def _read_input(self, path_or_text: str) -> str:
        path = Path(path_or_text)
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
        return path_or_text

    def cli(self, argv: list[str] | None = None) -> None:
        """Run the DevApp as a command-line application."""
        parser = argparse.ArgumentParser(prog=self.name, description=self.description)
        sub = parser.add_subparsers(dest="command")

        for cmd in self.commands.values():
            p = sub.add_parser(cmd.name, help=cmd.help)
            if cmd.requires_input:
                p.add_argument("input", help="Input text or file path")
            p.set_defaults(_dev_command=cmd)

        if self._programs:
            p = sub.add_parser("run", help="Run a registered program")
            p.add_argument("program", choices=sorted(self._programs.keys()))
            p.add_argument("--code", help="Code input or file path")
            p.add_argument(
                "--context",
                action="append",
                metavar="KEY=VALUE",
                help="Additional context values",
            )
            p.set_defaults(_dev_builtin="run_program")

        args = parser.parse_args(argv)
        if not args.command:
            parser.print_help()
            sys.exit(1)

        if getattr(args, "_dev_builtin", None) == "run_program":
            context: dict[str, str] = {}
            if args.code:
                context["code"] = self._read_input(args.code)
            if args.context:
                for pair in args.context:
                    key, _, value = pair.partition("=")
                    context[key] = value
            results = self.run_program(args.program, context)
            if self.runtime is not None:
                print(self.runtime.summarize(results))
            else:
                for result in results:
                    print(f"## {result.name}\n{result.output}\n")
            return

        cmd = args._dev_command
        if cmd.requires_input:
            print(cmd.handler(self._read_input(args.input)))
        else:
            print(cmd.handler())
