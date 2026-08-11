"""ProgramComposer — fluent builder for DevProgram workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.program import DevProgram, ProgramTask


class ProgramComposer:
    """Build DevProgram workflows with a fluent, chainable API.

    ProgramComposer lets developers assemble multi-step AI programs in Python
  without writing JSON/YAML by hand. Each method adds a task and returns self
  for chaining.
    """

    def __init__(self, assistant: CodeAssistant, name: str = "program") -> None:
        self._assistant = assistant
        self._name = name
        self._tasks: list[ProgramTask] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def task_count(self) -> int:
        return len(self._tasks)

    def _add(self, name: str, action: str, *, input_key: str = "code", **kwargs: Any) -> ProgramComposer:
        if action not in DevProgram.SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported action '{action}'. "
                f"Supported: {', '.join(sorted(DevProgram.SUPPORTED_ACTIONS))}"
            )
        self._tasks.append(ProgramTask(name=name, action=action, input_key=input_key, kwargs=kwargs))
        return self

    def review(self, name: str = "review", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "review", **kwargs)

    def explain(self, name: str = "explain", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "explain", **kwargs)

    def debug(self, name: str = "debug", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "debug", **kwargs)

    def refactor(self, name: str = "refactor", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "refactor", **kwargs)

    def security(self, name: str = "security", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "security", **kwargs)

    def tests(self, name: str = "tests", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "tests", **kwargs)

    def docstring(self, name: str = "docstring", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "docstring", **kwargs)

    def performance(self, name: str = "performance", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "performance", **kwargs)

    def architecture(self, name: str = "architecture", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "architecture", **kwargs)

    def generate(self, name: str = "generate", **kwargs: Any) -> ProgramComposer:
        return self._add(name, "generate", **kwargs)

    def step(
        self,
        name: str,
        action: str,
        *,
        input_key: str = "code",
        **kwargs: Any,
    ) -> ProgramComposer:
        """Add a custom step with any supported action."""
        return self._add(name, action, input_key=input_key, **kwargs)

    def build(self) -> DevProgram:
        """Return the assembled DevProgram."""
        program = DevProgram(name=self._name, assistant=self._assistant, tasks=list(self._tasks))
        errors = program.validate()
        if errors:
            raise ValueError(f"Invalid program: {'; '.join(errors)}")
        return program

    def save(self, path: str | Path) -> DevProgram:
        """Build and save the program to a JSON or YAML file."""
        program = self.build()
        program.save(path)
        return program

    @classmethod
    def from_program(cls, program: DevProgram) -> ProgramComposer:
        """Create a composer from an existing program for editing."""
        composer = cls(program.assistant, program.name)
        composer._tasks = list(program.tasks)
        return composer
