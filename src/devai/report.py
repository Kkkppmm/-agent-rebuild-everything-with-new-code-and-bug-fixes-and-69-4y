"""Export program and workflow results to JSON and Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from devai.program import ProgramResult
from devai.workflow import WorkflowResult


@dataclass
class ProgramReport:
    """Structured report for DevProgram or DevWorkflow execution results."""

    title: str
    source: str
    results: list[ProgramResult] | None = None
    workflow: WorkflowResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_program_results(
        cls,
        results: list[ProgramResult],
        *,
        title: str = "Program Report",
        program_name: str = "program",
        metadata: dict[str, Any] | None = None,
    ) -> ProgramReport:
        """Create a report from a list of ProgramResult objects."""
        return cls(
            title=title,
            source=program_name,
            results=results,
            metadata=metadata or {},
        )

    @classmethod
    def from_workflow(cls, workflow_result: WorkflowResult) -> ProgramReport:
        """Create a report from a WorkflowResult."""
        return cls(
            title=f"Workflow: {workflow_result.name}",
            source=workflow_result.name,
            workflow=workflow_result,
            metadata={
                "duration_seconds": workflow_result.duration_seconds,
                "context_keys": list(workflow_result.context.keys()),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a dictionary."""
        payload: dict[str, Any] = {
            "title": self.title,
            "source": self.source,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }
        if self.results is not None:
            payload["results"] = [
                {"name": r.name, "action": r.action, "output": r.output}
                for r in self.results
            ]
        if self.workflow is not None:
            payload["workflow"] = {
                "name": self.workflow.name,
                "duration_seconds": self.workflow.duration_seconds,
                "context": self.workflow.context,
                "steps": [
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
                ],
            }
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        """Export the report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Export the report as Markdown."""
        lines = [f"# {self.title}", "", f"**Source:** {self.source}", ""]
        if self.metadata:
            lines.append("## Metadata")
            for key, value in self.metadata.items():
                lines.append(f"- **{key}:** {value}")
            lines.append("")

        if self.results is not None:
            lines.append("## Results")
            for result in self.results:
                lines.append(f"### {result.name} ({result.action})")
                lines.append("")
                lines.append(result.output)
                lines.append("")

        if self.workflow is not None:
            lines.append("## Workflow Steps")
            for step in self.workflow.steps:
                group = f" [group: {step.parallel_group}]" if step.parallel_group else ""
                lines.append(
                    f"### {step.name}{group} ({step.duration_seconds:.2f}s)"
                )
                lines.append("")
                lines.append(step.output)
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def step_summaries(self) -> list[dict[str, Any]]:
        """Return a flat list of step summaries for CI or logging."""
        summaries: list[dict[str, Any]] = []
        if self.results is not None:
            for result in self.results:
                summaries.append(
                    {
                        "name": result.name,
                        "action": result.action,
                        "output_length": len(result.output),
                    }
                )
        if self.workflow is not None:
            for step in self.workflow.steps:
                summaries.append(
                    {
                        "name": step.name,
                        "program_name": step.program_name,
                        "duration_seconds": step.duration_seconds,
                        "task_count": len(step.results),
                    }
                )
        return summaries
