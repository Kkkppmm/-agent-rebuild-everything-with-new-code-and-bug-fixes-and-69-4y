"""Structured report export for DevAI program and workflow results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devai.program import ProgramResult
from devai.workflow import WorkflowResult


@dataclass
class ProgramReport:
    """Export program or workflow results as JSON or Markdown."""

    name: str
    results: list[ProgramResult] | None = None
    workflow: WorkflowResult | None = None
    context: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_program(
        cls,
        name: str,
        results: list[ProgramResult],
        *,
        context: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        """Build a report from program task results."""
        return cls(
            name=name,
            results=results,
            context=context or {},
            metadata=metadata or {},
        )

    @classmethod
    def from_workflow(cls, workflow: WorkflowResult) -> ProgramReport:
        """Build a report from a workflow result."""
        return cls(
            name=workflow.name,
            workflow=workflow,
            context=dict(workflow.context),
            metadata={"duration_seconds": workflow.duration_seconds},
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-friendly dict."""
        payload: dict[str, Any] = {
            "name": self.name,
            "created_at": self.created_at,
            "context": self.context,
            "metadata": self.metadata,
        }
        if self.results is not None:
            payload["type"] = "program"
            payload["tasks"] = [
                {"name": r.name, "action": r.action, "output": r.output}
                for r in self.results
            ]
        if self.workflow is not None:
            payload["type"] = "workflow"
            payload["duration_seconds"] = self.workflow.duration_seconds
            payload["steps"] = [
                {
                    "name": step.name,
                    "program_name": step.program_name,
                    "duration_seconds": step.duration_seconds,
                    "parallel_group": step.parallel_group,
                    "tasks": [
                        {"name": r.name, "action": r.action, "output": r.output}
                        for r in step.results
                    ],
                }
                for step in self.workflow.steps
            ]
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        """Export the report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Export the report as Markdown."""
        lines = [f"# DevAI Report: {self.name}", ""]
        lines.append(f"_Generated: {self.created_at}_")
        lines.append("")

        if self.context:
            lines.append("## Context")
            lines.append("")
            for key, value in self.context.items():
                preview = value[:200] + "..." if len(value) > 200 else value
                lines.append(f"- **{key}**: `{preview}`")
            lines.append("")

        if self.results is not None:
            lines.append("## Program Results")
            lines.append("")
            for result in self.results:
                lines.append(f"### {result.name} (`{result.action}`)")
                lines.append("")
                lines.append(result.output)
                lines.append("")

        if self.workflow is not None:
            lines.append(f"## Workflow: {self.workflow.name}")
            lines.append("")
            lines.append(
                f"Duration: {self.workflow.duration_seconds:.2f}s | "
                f"Steps: {len(self.workflow.steps)}"
            )
            lines.append("")
            for step in self.workflow.steps:
                group = f" (group: {step.parallel_group})" if step.parallel_group else ""
                lines.append(
                    f"### {step.name}{group} — {step.duration_seconds:.2f}s"
                )
                lines.append("")
                lines.append(step.output)
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def save(
        self,
        path: str | Path,
        *,
        format: str | None = None,
    ) -> Path:
        """Write the report to a file (json or markdown)."""
        target = Path(path)
        fmt = format or target.suffix.lstrip(".").lower()
        if fmt in {"json", "jsonl"}:
            target.write_text(self.to_json(), encoding="utf-8")
        elif fmt in {"md", "markdown"}:
            target.write_text(self.to_markdown(), encoding="utf-8")
        else:
            raise ValueError(f"Unsupported report format: {fmt}")
        return target
