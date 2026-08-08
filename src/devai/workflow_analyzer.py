"""WorkflowAnalyzer — audit GitHub Actions workflows for CI security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOW_DIR = ".github/workflows"

UNPINNED_ACTION_PATTERN = re.compile(
    r"uses:\s*[^\s@]+@(main|master|latest|v\d+)\s*$",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)


@dataclass
class WorkflowFinding:
    """A security or best-practice issue in a GitHub Actions workflow."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class WorkflowInfo:
    """Parsed metadata about a workflow file."""

    path: str
    jobs: int = 0
    has_permissions: bool = False
    uses_pull_request_target: bool = False


@dataclass
class WorkflowStats:
    """Aggregate workflow analysis statistics."""

    workflows: int
    jobs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class WorkflowAnalyzer:
    """Audit GitHub Actions workflows for CI/CD security risks.

    Scans for unpinned actions, overly broad permissions, secrets in env,
    curl-pipe-to-shell patterns, and pull_request_target usage.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WorkflowFinding] | None = None
        self._stats: WorkflowStats | None = None
        self._infos: list[WorkflowInfo] | None = None

    def workflow_files(self) -> list[Path]:
        """Return workflow YAML paths found in the project."""
        workflow_root = self.root / WORKFLOW_DIR
        if not workflow_root.is_dir():
            return []
        found: list[Path] = []
        for path in sorted(workflow_root.iterdir()):
            if path.is_file() and path.suffix in (".yml", ".yaml"):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[WorkflowFinding], WorkflowInfo]:
        findings: list[WorkflowFinding] = []
        rel = str(path.relative_to(self.root))
        info = WorkflowInfo(path=rel)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, info

        in_permissions = False
        permissions_content = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            stripped = line.strip()
            lower = stripped.lower()

            if stripped == "jobs:":
                continue
            if re.match(r"^\S+:\s*$", stripped) and "jobs" not in stripped:
                if stripped.endswith(":") and line.startswith("  ") and not line.startswith("    "):
                    info.jobs += 1

            if lower.startswith("on:") and "pull_request_target" in lower:
                info.uses_pull_request_target = True
                findings.append(
                    WorkflowFinding(
                        kind="pull_request_target",
                        severity="high",
                        message="pull_request_target can expose secrets to untrusted forks — review carefully",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if "pull_request_target" in lower and "on:" not in lower:
                info.uses_pull_request_target = True

            if lower.startswith("permissions:"):
                in_permissions = True
                info.has_permissions = True
                permissions_content = stripped
                if "write-all" in lower or "contents: write" in lower and "pull-requests: write" in lower:
                    pass
                continue

            if in_permissions:
                permissions_content += " " + lower
                if not line.startswith(" ") or line.strip() == permissions_content.strip():
                    in_permissions = False
                if "write-all" in lower:
                    findings.append(
                        WorkflowFinding(
                            kind="write_all_permissions",
                            severity="high",
                            message="permissions: write-all grants excessive access",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if "uses:" in lower:
                uses_part = stripped
                if uses_part.startswith("- "):
                    uses_part = uses_part[2:].strip()
                if UNPINNED_ACTION_PATTERN.search(uses_part):
                    findings.append(
                        WorkflowFinding(
                            kind="unpinned_action",
                            severity="medium",
                            message="action not pinned to a commit SHA — pin for supply-chain security",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if "@main" in uses_part.lower() or "@master" in uses_part.lower():
                    findings.append(
                        WorkflowFinding(
                            kind="floating_action_ref",
                            severity="medium",
                            message="action references a floating branch (@main/@master)",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if lower.startswith("run:") and CURL_PIPE_SHELL_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in CI is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if lower.startswith("env:") or (lower.startswith("- ") and "=" in stripped):
                if SECRET_ENV_PATTERN.search(stripped) and "=" in stripped:
                    val = stripped.split("=", 1)[-1].strip().strip("'\"")
                    if val and not val.startswith("${{") and val not in ("''", '""'):
                        findings.append(
                            WorkflowFinding(
                                kind="hardcoded_secret",
                                severity="high",
                                message="potential hardcoded secret in workflow env",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
            elif ":" in stripped and SECRET_ENV_PATTERN.search(stripped):
                key, _, val = stripped.partition(":")
                if key.strip().isupper() or SECRET_ENV_PATTERN.search(key):
                    val = val.strip().strip("'\"")
                    if val and not val.startswith("${{") and val not in ("''", '""'):
                        findings.append(
                            WorkflowFinding(
                                kind="hardcoded_secret",
                                severity="high",
                                message="potential hardcoded secret in workflow env",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

        if info.jobs > 0 and not info.has_permissions:
            findings.append(
                WorkflowFinding(
                    kind="missing_permissions",
                    severity="low",
                    message="no explicit permissions block — workflow uses default GITHUB_TOKEN scope",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[WorkflowFinding]:
        """Scan workflow files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[WorkflowFinding] = []
        infos: list[WorkflowInfo] = []
        paths = self.workflow_files()
        total_jobs = 0

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            total_jobs += info.jobs

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = WorkflowStats(
            workflows=len(paths),
            jobs=total_jobs,
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> WorkflowStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[WorkflowInfo]:
        """Return parsed workflow metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no workflows)."""
        self.analyze()
        stats = self.stats
        if stats.workflows == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.workflows == 0:
            return "Workflows: none found"
        return (
            f"Workflows: {stats.workflows} file(s), {stats.jobs} job(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitHub Actions workflow analysis:",
            f"  workflows: {stats.workflows}",
            f"  jobs: {stats.jobs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
