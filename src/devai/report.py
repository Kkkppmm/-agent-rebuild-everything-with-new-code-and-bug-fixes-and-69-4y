"""Export DevAI program and workflow results to JSON and Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devai.program import ProgramResult
from devai.workflow import WorkflowResult


def _program_results_to_dict(results: list[ProgramResult]) -> list[dict[str, str]]:
    return [
        {"name": result.name, "action": result.action, "output": result.output}
        for result in results
    ]


def _workflow_result_to_dict(result: WorkflowResult) -> dict[str, Any]:
    return {
        "name": result.name,
        "duration_seconds": round(result.duration_seconds, 3),
        "context": dict(result.context),
        "steps": [
            {
                "name": step.name,
                "program_name": step.program_name,
                "duration_seconds": round(step.duration_seconds, 3),
                "parallel_group": step.parallel_group,
                "results": _program_results_to_dict(step.results),
            }
            for step in result.steps
        ],
    }


@dataclass
class ProgramReport:
    """Structured report for DevAI program or workflow runs."""

    title: str
    results: list[ProgramResult] | None = None
    workflow: WorkflowResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "title": self.title,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
        }
        if self.results is not None:
            payload["type"] = "program"
            payload["results"] = _program_results_to_dict(self.results)
        elif self.workflow is not None:
            payload["type"] = "workflow"
            payload["workflow"] = _workflow_result_to_dict(self.workflow)
        else:
            payload["type"] = "empty"
            payload["results"] = []
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Format the report as Markdown."""
        lines = [f"# {self.title}", ""]
        lines.append(f"*Generated at {self.generated_at}*")
        lines.append("")
        if self.metadata:
            lines.append("## Metadata")
            lines.append("")
            for key, value in self.metadata.items():
                lines.append(f"- **{key}**: {value}")
            lines.append("")
        if self.workflow is not None:
            lines.append(self.workflow.summarize())
        elif self.results:
            for result in self.results:
                lines.append(f"## {result.name} (`{result.action}`)")
                lines.append("")
                lines.append(result.output)
                lines.append("")
        else:
            lines.append("_No results._")
        return "\n".join(lines).rstrip() + "\n"

    def save(self, path: str | Path, *, format: str | None = None) -> Path:
        """Write the report to a file (json or md inferred from extension)."""
        target = Path(path)
        fmt = format or target.suffix.lstrip(".").lower()
        if fmt in ("json",):
            target.write_text(self.to_json(), encoding="utf-8")
        elif fmt in ("md", "markdown"):
            target.write_text(self.to_markdown(), encoding="utf-8")
        else:
            raise ValueError(f"Unsupported report format: {fmt!r} (use json or md)")
        return target

    @classmethod
    def from_program(
        cls,
        results: list[ProgramResult],
        *,
        title: str = "DevAI Program Report",
        **metadata: Any,
    ) -> ProgramReport:
        """Create a report from program step results."""
        return cls(title=title, results=results, metadata=metadata)

    @classmethod
    def from_workflow(
        cls,
        workflow: WorkflowResult,
        *,
        title: str | None = None,
        **metadata: Any,
    ) -> ProgramReport:
        """Create a report from a workflow result."""
        return cls(
            title=title or f"DevAI Workflow: {workflow.name}",
            workflow=workflow,
            metadata=metadata,
        )
