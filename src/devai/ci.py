"""CI/CD helpers for integrating DevAI into pipelines and pull requests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from devai.program import ProgramResult
from devai.schemas import CodeReviewResult, PerfReviewResult, SecurityAuditResult


@dataclass
class CIReport:
    """Structured report for CI pipelines."""

    title: str
    body: str
    passed: bool
    annotations: list[dict[str, Any]]

    def to_github_comment(self) -> str:
        """Format as a GitHub pull request comment."""
        status = "✅ Passed" if self.passed else "❌ Failed"
        return f"## {self.title}\n\n**Status:** {status}\n\n{self.body}"

    def to_github_annotations(self) -> list[dict[str, Any]]:
        """Return GitHub Actions annotation payloads."""
        return self.annotations

    def to_json(self) -> str:
        """Serialize the report to JSON."""
        return json.dumps(
            {
                "title": self.title,
                "body": self.body,
                "passed": self.passed,
                "annotations": self.annotations,
            },
            indent=2,
        )


def _severity_level(severity: str) -> str:
    return severity.lower()


def report_from_review(
    result: CodeReviewResult,
    *,
    title: str = "DevAI Code Review",
    fail_below: int = 5,
) -> CIReport:
    """Build a CI report from a structured code review."""
    passed = result.score >= fail_below
    lines = [f"**Score:** {result.score}/10", "", result.summary, ""]

    annotations: list[dict[str, Any]] = []
    if result.issues:
        lines.append("### Issues")
        for issue in result.issues:
            line_ref = f" (line {issue.line})" if issue.line else ""
            lines.append(f"- **{issue.severity.upper()}**{line_ref}: {issue.message}")
            if issue.suggestion:
                lines.append(f"  - Suggestion: {issue.suggestion}")
            if issue.line is not None and _severity_level(issue.severity) in {
                "high",
                "critical",
            }:
                annotations.append(
                    {
                        "path": "code",
                        "start_line": issue.line,
                        "end_line": issue.line,
                        "annotation_level": "failure",
                        "message": issue.message,
                        "title": f"DevAI: {issue.severity}",
                    }
                )

    return CIReport(
        title=title,
        body="\n".join(lines),
        passed=passed,
        annotations=annotations,
    )


def report_from_security(
    result: SecurityAuditResult,
    *,
    title: str = "DevAI Security Audit",
    fail_on: set[str] | None = None,
) -> CIReport:
    """Build a CI report from a structured security audit."""
    fail_on = fail_on or {"high", "critical"}
    risk = _severity_level(result.risk_level)
    passed = risk not in fail_on
    lines = [f"**Risk level:** {result.risk_level.upper()}", "", result.summary, ""]

    annotations: list[dict[str, Any]] = []
    if result.findings:
        lines.append("### Findings")
        for finding in result.findings:
            lines.append(
                f"- **{finding.severity.upper()}** [{finding.category}]: {finding.description}"
            )
            if finding.remediation:
                lines.append(f"  - Remediation: {finding.remediation}")
            if _severity_level(finding.severity) in fail_on:
                annotations.append(
                    {
                        "annotation_level": "failure",
                        "message": finding.description,
                        "title": f"DevAI Security: {finding.category}",
                    }
                )

    return CIReport(
        title=title,
        body="\n".join(lines),
        passed=passed,
        annotations=annotations,
    )


def report_from_performance(
    result: PerfReviewResult,
    *,
    title: str = "DevAI Performance Review",
    fail_on: set[str] | None = None,
) -> CIReport:
    """Build a CI report from a structured performance review."""
    fail_on = fail_on or {"high"}
    high_impact = [
        issue for issue in result.issues if _severity_level(issue.impact) in fail_on
    ]
    passed = not high_impact
    lines = [result.summary, ""]

    annotations: list[dict[str, Any]] = []
    if result.issues:
        lines.append("### Performance Issues")
        for issue in result.issues:
            lines.append(f"- **{issue.impact.upper()}** [{issue.area}]: {issue.description}")
            if issue.fix:
                lines.append(f"  - Fix: {issue.fix}")
            if _severity_level(issue.impact) in fail_on:
                annotations.append(
                    {
                        "annotation_level": "warning",
                        "message": issue.description,
                        "title": f"DevAI Performance: {issue.area}",
                    }
                )

    return CIReport(
        title=title,
        body="\n".join(lines),
        passed=passed,
        annotations=annotations,
    )


def report_from_program(
    results: list[ProgramResult],
    *,
    title: str = "DevAI Program Report",
) -> CIReport:
    """Build a CI report from DevProgram results."""
    lines = []
    for result in results:
        lines.append(f"### {result.name} ({result.action})")
        lines.append(result.output)
        lines.append("")

    body = "\n".join(lines).strip()
    passed = not any(
        keyword in body.lower()
        for keyword in ("critical", "vulnerability", "must fix", "blocking")
    )

    return CIReport(
        title=title,
        body=body,
        passed=passed,
        annotations=[],
    )
