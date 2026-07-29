"""Export program and workflow results to JSON and Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.program import ProgramResult
from devai.workflow import WorkflowResult


@dataclass
class ProgramReport:
    """Serialize DevAI program or workflow output for CI, logs, and artifacts."""

    name: str
    results: list[ProgramResult] = field(default_factory=list)
    workflow: WorkflowResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_results(
        cls,
        name: str,
        results: list[ProgramResult],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        """Build a report from a list of program task results."""
        return cls(name=name, results=list(results), metadata=metadata or {})

    @classmethod
    def from_workflow(
        cls,
        workflow_result: WorkflowResult,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        """Build a report from a workflow run."""
        return cls(
            name=workflow_result.name,
            workflow=workflow_result,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a JSON-serializable dictionary."""
        payload: dict[str, Any] = {
            "name": self.name,
            "metadata": self.metadata,
        }
        if self.workflow is not None:
            payload["type"] = "workflow"
            payload["duration_seconds"] = self.workflow.duration_seconds
            payload["steps"] = [
                {
                    "name": step.name,
                    "program_name": step.program_name,
                    "duration_seconds": step.duration_seconds,
                    "parallel_group": step.parallel_group,
                    "results": [
                        {"name": r.name, "action": r.action, "output": r.output}
                        for r in step.results
                    ],
                }
                for step in self.workflow.steps
            ]
        else:
            payload["type"] = "program"
            payload["results"] = [
                {"name": r.name, "action": r.action, "output": r.output}
                for r in self.results
            ]
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Format the report as Markdown."""
        if self.workflow is not None:
            body = self.workflow.summarize()
            footer = f"\n\n---\n*Duration: {self.workflow.duration_seconds:.2f}s*"
            return body + footer

        lines = [f"# Program: {self.name}\n"]
        for result in self.results:
            lines.append(f"## {result.name} (`{result.action}`)\n")
            lines.append(result.output)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def save(self, path: str | Path) -> Path:
        """Save the report to a file (format inferred from extension)."""
        target = Path(path)
        suffix = target.suffix.lower()
        if suffix == ".json":
            target.write_text(self.to_json(), encoding="utf-8")
        elif suffix in {".md", ".markdown"}:
            target.write_text(self.to_markdown(), encoding="utf-8")
        else:
            raise ValueError("path must end with .json, .md, or .markdown")
        return target
