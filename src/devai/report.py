"""Program and workflow result reporting."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from devai.program import ProgramResult
from devai.workflow import WorkflowResult


@dataclass
class ProgramReport:
    """Export program or workflow results as JSON or Markdown."""

    name: str
    results: list[ProgramResult] | WorkflowResult
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        if isinstance(self.results, WorkflowResult):
            payload: dict[str, Any] = {
                "name": self.name,
                "type": "workflow",
                "workflow": self.results.name,
                "duration_seconds": self.results.duration_seconds,
                "steps": [
                    {
                        "name": step.name,
                        "program_name": step.program_name,
                        "duration_seconds": step.duration_seconds,
                        "results": [asdict(r) for r in step.results],
                    }
                    for step in self.results.steps
                ],
            }
        else:
            payload = {
                "name": self.name,
                "type": "program",
                "tasks": [asdict(r) for r in self.results],
            }
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        if isinstance(self.results, WorkflowResult):
            return self.results.summarize()
        parts = [f"# Program: {self.name}\n"]
        for result in self.results:
            parts.append(f"## {result.name} ({result.action})\n\n{result.output}")
        return "\n\n---\n\n".join(parts)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        if path.suffix == ".json":
            path.write_text(self.to_json(), encoding="utf-8")
        else:
            path.write_text(self.to_markdown(), encoding="utf-8")

    @classmethod
    def from_program(
        cls,
        name: str,
        results: list[ProgramResult],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        return cls(name=name, results=results, metadata=metadata)

    @classmethod
    def from_workflow(
        cls,
        result: WorkflowResult,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        return cls(name=result.name, results=result, metadata=metadata)
