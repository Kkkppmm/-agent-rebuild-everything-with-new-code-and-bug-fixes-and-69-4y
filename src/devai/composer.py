"""ProgramComposer — fluent API for building DevProgram workflows in Python."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.assistant import CodeAssistant
from devai.program import DevProgram, ProgramTask


@dataclass
class ProgramComposer:
    """Fluent builder for DevProgram workflows.

    ProgramComposer lets developers define multi-step AI programs in Python
  without writing JSON/YAML — ideal for scripts and programmatic automation.

    Example::

        composer = ProgramComposer("my-audit", assistant)
        program = (
            composer
            .step("review", "review", input_key="code")
            .step("security", "security_audit", input_key="review")
            .step("tests", "generate_tests", input_key="code")
            .build()
        )
    """

    name: str
    assistant: CodeAssistant
    _tasks: list[ProgramTask] = field(default_factory=list, init=False, repr=False)
    _description: str | None = field(default=None, init=False, repr=False)
    _tags: list[str] = field(default_factory=list, init=False, repr=False)

    def step(
        self,
        name: str,
        action: str,
        *,
        input_key: str = "code",
        **kwargs: Any,
    ) -> ProgramComposer:
        """Add a step to the program. Returns self for chaining."""
        self._tasks.append(
            ProgramTask(name=name, action=action, input_key=input_key, kwargs=kwargs)
        )
        return self

    def describe(self, description: str) -> ProgramComposer:
        """Set a human-readable description."""
        self._description = description
        return self

    def tag(self, *tags: str) -> ProgramComposer:
        """Add tags for library search and organization."""
        self._tags.extend(tags)
        return self

    def build(self) -> DevProgram:
        """Build the DevProgram from accumulated steps."""
        return DevProgram(name=self.name, assistant=self.assistant, tasks=list(self._tasks))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the composed program to a dict (for JSON/YAML export)."""
        data: dict[str, Any] = {
            "name": self.name,
            "tasks": [task.to_dict() for task in self._tasks],
        }
        if self._description:
            data["description"] = self._description
        if self._tags:
            data["tags"] = self._tags
        return data

    def reset(self) -> ProgramComposer:
        """Clear all steps and metadata."""
        self._tasks.clear()
        self._description = None
        self._tags.clear()
        return self
