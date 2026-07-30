"""Compose DevProgram workflows from presets and custom tasks."""

from __future__ import annotations

from typing import Any

from devai.assistant import CodeAssistant
from devai.presets import get_preset
from devai.program import DevProgram, ProgramTask


class ProgramComposer:
    """Build composite DevPrograms by merging presets and custom steps."""

    def __init__(self, assistant: CodeAssistant, name: str = "composed") -> None:
        self._assistant = assistant
        self._name = name
        self._tasks: list[ProgramTask] = []
        self._descriptions: list[str] = []

    @classmethod
    def from_presets(
        cls,
        assistant: CodeAssistant,
        preset_names: list[str],
        *,
        name: str = "composed",
    ) -> ProgramComposer:
        """Create a composer pre-loaded with tasks from built-in presets."""
        composer = cls(assistant, name=name)
        for preset_name in preset_names:
            composer.add_preset(preset_name)
        return composer

    def add_preset(self, preset_name: str) -> ProgramComposer:
        """Append all tasks from a built-in preset."""
        program = get_preset(preset_name, self._assistant)
        self._tasks.extend(program.tasks)
        if program.name:
            self._descriptions.append(program.name)
        return self

    def add_task(
        self,
        name: str,
        action: str,
        *,
        input_key: str = "code",
        kwargs: dict[str, Any] | None = None,
    ) -> ProgramComposer:
        """Append a single custom task."""
        self._tasks.append(
            ProgramTask(
                name=name,
                action=action,
                input_key=input_key,
                kwargs=kwargs or {},
            )
        )
        return self

    def with_prefix(self, prefix: str) -> ProgramComposer:
        """Prefix all task names to avoid collisions when merging presets."""
        self._tasks = [
            ProgramTask(
                name=f"{prefix}_{task.name}",
                action=task.action,
                input_key=task.input_key,
                kwargs=dict(task.kwargs),
            )
            for task in self._tasks
        ]
        return self

    def dedupe_actions(self) -> ProgramComposer:
        """Remove duplicate actions, keeping the first occurrence."""
        seen: set[str] = set()
        unique: list[ProgramTask] = []
        for task in self._tasks:
            if task.action in seen:
                continue
            seen.add(task.action)
            unique.append(task)
        self._tasks = unique
        return self

    def build(self) -> DevProgram:
        """Materialize the composed program."""
        return DevProgram(
            name=self._name,
            assistant=self._assistant,
            tasks=list(self._tasks),
        )

    @property
    def task_count(self) -> int:
        return len(self._tasks)

    def describe(self) -> str:
        """Summarize composed steps for dry-run previews."""
        lines = [f"Program: {self._name} ({self.task_count} tasks)"]
        if self._descriptions:
            lines.append(f"Sources: {', '.join(self._descriptions)}")
        for i, task in enumerate(self._tasks, 1):
            lines.append(f"  {i}. {task.name} → {task.action} (input: {task.input_key})")
        return "\n".join(lines)
