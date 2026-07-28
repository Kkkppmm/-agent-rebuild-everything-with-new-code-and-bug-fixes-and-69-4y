"""CI report helpers for GitHub PR comments and Actions annotations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.program import ProgramResult
from devai.schemas import CodeReviewResult, PerfReviewResult, SecurityAuditResult


@dataclass
class CIAnnotation:
    """A single CI annotation for GitHub Actions or other CI systems."""

    level: str = "notice"
    message: str = ""
    file: str | None = None
    line: int | None = None
    col: int | None = None
    title: str | None = None

    def to_github_actions(self) -> str:
        """Format as a GitHub Actions workflow command."""
        level = self.level if self.level in ("error", "warning", "notice") else "notice"
        parts: list[str] = []
        if self.file:
            parts.append(f"file={self.file}")
        if self.line is not None:
            parts.append(f"line={self.line}")
        if self.col is not None:
            parts.append(f"col={self.col}")
        if self.title:
            parts.append(f"title={self.title}")
        location = ",".join(parts)
        prefix = f"::{level} {location}::" if location else f"::{level}::"
        return f"{prefix}{self.message}"


@dataclass
class CIReport:
    """Aggregated CI report from DevAI program or structured review results."""

    title: str = "DevAI CI Report"
    sections: list[tuple[str, str]] = field(default_factory=list)
    annotations: list[CIAnnotation] = field(default_factory=list)
    passed: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_section(self, heading: str, body: str) -> None:
        """Add a markdown section to the report."""
        self.sections.append((heading, body))

    def add_annotation(
        self,
        message: str,
        *,
        level: str = "notice",
        file: str | None = None,
        line: int | None = None,
        col: int | None = None,
        title: str | None = None,
    ) -> None:
        """Add a CI annotation."""
        self.annotations.append(
            CIAnnotation(
                level=level,
                message=message,
                file=file,
                line=line,
                col=col,
                title=title,
            )
        )
        if level == "error":
            self.passed = False

    def to_github_comment(self) -> str:
        """Format the report as a GitHub pull request comment."""
        status = "✅ Passed" if self.passed else "❌ Failed"
        lines = [f"## {self.title}", "", f"**Status:** {status}", ""]
        for heading, body in self.sections:
            lines.append(f"### {heading}")
            lines.append("")
            lines.append(body.strip())
            lines.append("")
        if self.metadata:
            lines.append("---")
            lines.append("")
            for key, value in self.metadata.items():
                lines.append(f"- **{key}:** {value}")
        return "\n".join(lines).strip()

    def to_github_actions_annotations(self) -> list[str]:
        """Return GitHub Actions workflow command strings."""
        return [annotation.to_github_actions() for annotation in self.annotations]

    def write_github_actions_annotations(self) -> None:
        """Print GitHub Actions annotations to stdout."""
        for line in self.to_github_actions_annotations():
            print(line)


def _severity_to_level(severity: str) -> str:
    normalized = severity.lower()
    if normalized in ("critical", "high"):
        return "error"
    if normalized in ("medium", "moderate"):
        return "warning"
    return "notice"


def report_from_program_results(
    results: list[ProgramResult],
    *,
    title: str = "DevAI CI Report",
    fail_on_security: bool = True,
) -> CIReport:
    """Build a CI report from DevProgram results."""
    report = CIReport(title=title)
    for result in results:
        report.add_section(f"{result.name} ({result.action})", result.output)
        if fail_on_security and result.action == "security":
            lowered = result.output.lower()
            if any(word in lowered for word in ("critical", "high risk", "vulnerability")):
                report.add_annotation(
                    f"Security issues found in {result.name}",
                    level="error",
                    title="Security",
                )
    return report


def report_from_structured_review(
    review: CodeReviewResult,
    *,
    title: str = "Code Review",
    min_score: int = 7,
    file: str | None = None,
) -> CIReport:
    """Build a CI report from a structured code review."""
    report = CIReport(title=title)
    report.add_section(
        "Summary",
        f"Score: {review.score}/10\n\n{review.summary}",
    )
    report.metadata["score"] = review.score
    if review.score < min_score:
        report.passed = False
        report.add_annotation(
            f"Code review score {review.score} below minimum {min_score}",
            level="error",
            title="Score Gate",
        )
    for issue in review.issues:
        report.add_annotation(
            issue.message,
            level=_severity_to_level(issue.severity),
            file=file,
            line=issue.line,
            title=issue.severity,
        )
    return report


def report_from_security_audit(
    audit: SecurityAuditResult,
    *,
    title: str = "Security Audit",
    max_risk: str = "medium",
) -> CIReport:
    """Build a CI report from a structured security audit."""
    report = CIReport(title=title)
    report.add_section("Summary", f"Risk: {audit.risk_level}\n\n{audit.summary}")
    report.metadata["risk_level"] = audit.risk_level
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if risk_order.get(audit.risk_level.lower(), 0) > risk_order.get(max_risk.lower(), 1):
        report.passed = False
        report.add_annotation(
            f"Risk level {audit.risk_level} exceeds maximum {max_risk}",
            level="error",
            title="Security Gate",
        )
    for finding in audit.findings:
        report.add_annotation(
            finding.description,
            level=_severity_to_level(finding.severity),
            title=f"{finding.category}: {finding.severity}",
        )
    return report


def report_from_performance_review(
    perf: PerfReviewResult,
    *,
    title: str = "Performance Review",
) -> CIReport:
    """Build a CI report from a structured performance review."""
    report = CIReport(title=title)
    report.add_section("Summary", perf.summary)
    for issue in perf.issues:
        report.add_annotation(
            issue.description,
            level=_severity_to_level(issue.impact),
            title=f"{issue.area}: {issue.impact}",
        )
    return report


def merge_reports(*reports: CIReport, title: str | None = None) -> CIReport:
    """Merge multiple CI reports into one."""
    merged = CIReport(title=title or "DevAI CI Report")
    for report in reports:
        merged.sections.extend(report.sections)
        merged.annotations.extend(report.annotations)
        merged.metadata.update(report.metadata)
        if not report.passed:
            merged.passed = False
    return merged
