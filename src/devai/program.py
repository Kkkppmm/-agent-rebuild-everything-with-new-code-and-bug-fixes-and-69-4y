"""Declarative programs for scripting DevAI workflows."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant


@dataclass
class ProgramTask:
    """A single step in a DevAI program."""

    name: str
    action: str
    input_key: str = "code"
    kwargs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProgramTask:
        return cls(
            name=data["name"],
            action=data["action"],
            input_key=data.get("input_key", "code"),
            kwargs=data.get("kwargs", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "action": self.action,
        }
        if self.input_key != "code":
            payload["input_key"] = self.input_key
        if self.kwargs:
            payload["kwargs"] = self.kwargs
        return payload


@dataclass
class ProgramResult:
    """Output from a single program task."""

    name: str
    action: str
    output: str


@dataclass
class DevProgram:
    """Scriptable multi-step AI workflow for developers and programs."""

    name: str
    assistant: CodeAssistant
    tasks: list[ProgramTask] = field(default_factory=list)

    SUPPORTED_ACTIONS = frozenset(
        {
            "review",
            "explain",
            "debug",
            "refactor",
            "security",
            "tests",
            "docstring",
            "performance",
            "architecture",
            "generate",
            "type_hints",
            "review_diff",
            "fix_lint",
            "audit_deps",
            "dockerfile",
            "migration_plan",
            "api_design",
            "optimize_sql",
            "analyze_logs",
        }
    )

    def add(
        self,
        name: str,
        action: str,
        *,
        input_key: str = "code",
        **kwargs: Any,
    ) -> DevProgram:
        """Add a task to the program."""
        if action not in self.SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported action '{action}'. "
                f"Supported: {', '.join(sorted(self.SUPPORTED_ACTIONS))}"
            )
        self.tasks.append(
            ProgramTask(name=name, action=action, input_key=input_key, kwargs=kwargs)
        )
        return self

    @classmethod
    def from_dict(cls, data: dict[str, Any], assistant: CodeAssistant) -> DevProgram:
        """Load a program from a dictionary."""
        tasks = [ProgramTask.from_dict(task) for task in data.get("tasks", [])]
        return cls(name=data.get("name", "program"), assistant=assistant, tasks=tasks)

    @classmethod
    def from_json(cls, text: str, assistant: CodeAssistant) -> DevProgram:
        """Load a program from JSON."""
        return cls.from_dict(json.loads(text), assistant)

    @classmethod
    def from_file(cls, path: str | Path, assistant: CodeAssistant) -> DevProgram:
        """Load a program from a JSON file."""
        return cls.from_json(Path(path).read_text(encoding="utf-8"), assistant)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the program to a dictionary."""
        return {
            "name": self.name,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the program to JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path) -> None:
        """Save the program to a JSON file."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def _handler(self, action: str) -> Callable[..., str]:
        handlers: dict[str, Callable[..., str]] = {
            "review": self.assistant.review,
            "explain": self.assistant.explain,
            "debug": self.assistant.debug,
            "refactor": self.assistant.refactor,
            "security": self.assistant.security,
            "tests": self.assistant.tests,
            "docstring": self.assistant.docstring,
            "performance": self.assistant.performance,
            "architecture": self.assistant.architecture,
            "generate": self.assistant.generate,
            "type_hints": self.assistant.type_hints,
            "review_diff": self.assistant.review_diff,
            "fix_lint": self.assistant.fix_lint,
            "audit_deps": self.assistant.audit_deps,
            "dockerfile": self.assistant.dockerfile,
            "migration_plan": self.assistant.migration_plan,
            "api_design": self.assistant.api_design,
            "optimize_sql": self.assistant.optimize_sql,
            "analyze_logs": self.assistant.analyze_logs,
        }
        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"Unsupported action: {action}")
        return handler

    def _async_handler(self, action: str) -> Callable[..., Awaitable[str]] | None:
        async_handlers: dict[str, Callable[..., Awaitable[str]]] = {
            "review": self.assistant.areview,
        }
        return async_handlers.get(action)

    def run(self, context: dict[str, str]) -> list[ProgramResult]:
        """Execute all tasks and return ordered results."""
        results: list[ProgramResult] = []
        for task in self.tasks:
            handler = self._handler(task.action)
            primary = context.get(task.input_key, "")
            output = handler(primary, **task.kwargs)
            results.append(ProgramResult(name=task.name, action=task.action, output=output))
            context[task.name] = output
        return results

    async def arun(self, context: dict[str, str]) -> list[ProgramResult]:
        """Execute all tasks asynchronously where supported."""
        results: list[ProgramResult] = []
        for task in self.tasks:
            primary = context.get(task.input_key, "")
            async_handler = self._async_handler(task.action)
            if async_handler is not None:
                output = await async_handler(primary, **task.kwargs)
            else:
                output = self._handler(task.action)(primary, **task.kwargs)
            results.append(ProgramResult(name=task.name, action=task.action, output=output))
            context[task.name] = output
        return results

    def run_and_summarize(self, context: dict[str, str]) -> str:
        """Run the program and return a markdown summary."""
        results = self.run(context)
        parts = [f"## {result.name} ({result.action})\n\n{result.output}" for result in results]
        return "\n\n---\n\n".join(parts)
