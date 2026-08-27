"""WorkflowAnalyzer — audit GitHub Actions workflows for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOW_DIR = (".github", "workflows")

UNPINNED_REF_PATTERN = re.compile(
    r"uses:\s*[^\s@]+@(main|master|dev|nightly|latest)\b",
    re.IGNORECASE,
)
MUTABLE_TAG_PATTERN = re.compile(
    r"uses:\s*[^\s@]+@v\d+\b(?![.\d])",
    re.IGNORECASE,
)
PULL_REQUEST_TARGET_PATTERN = re.compile(r"^\s*pull_request_target\s*:", re.IGNORECASE)
WRITE_ALL_PERMISSIONS_PATTERN = re.compile(
    r"permissions:\s*(write-all|all)\b",
    re.IGNORECASE,
)
CONTENTS_WRITE_PATTERN = re.compile(r"^\s*contents:\s*write\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"run:\s*.*\$\{\{\s*github\.event\.[^}]+\}\}",
    re.IGNORECASE,
)
CHECKOUT_NO_PERSIST_PATTERN = re.compile(
    r"uses:\s*actions/checkout@[^\s]+",
    re.IGNORECASE,
)
PERSIST_CREDENTIALS_TRUE_PATTERN = re.compile(
    r"persist-credentials:\s*true\b",
    re.IGNORECASE,
)
UNSAFE_ENV_CONTEXT_PATTERN = re.compile(
    r"\$\{\{\s*env\.[A-Z0-9_]+\s*\}\}",
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
    triggers: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    uses_checkout: bool = False
    lines: int = 0


@dataclass
class WorkflowStats:
    """Aggregate workflow analysis statistics."""

    workflows: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_workflow_file(path: Path) -> bool:
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    parts = path.parts
    if len(parts) < 3:
        return False
    return parts[-3] == ".github" and parts[-2] == "workflows"


class WorkflowAnalyzer:
    """Audit GitHub Actions workflows for security risks and CI best practices.

    Scans for unpinned actions, dangerous ``pull_request_target`` usage,
    overly broad permissions, secrets in env blocks, script injection via
    event context, and curl-pipe-to-shell patterns in run steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WorkflowFinding] | None = None
        self._stats: WorkflowStats | None = None
        self._infos: list[WorkflowInfo] | None = None

    def workflows(self) -> list[Path]:
        """Return workflow file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_workflow_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[WorkflowFinding], WorkflowInfo]:
        findings: list[WorkflowFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, WorkflowInfo(path=rel)

        info = WorkflowInfo(path=rel, lines=len(raw_lines))
        in_on_block = False
        in_permissions = False
        in_env_block = False
        env_indent = 0
        has_pull_request_target = False
        checkout_lines: list[tuple[int, str]] = []

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line == "on:" or line.startswith("on:"):
                in_on_block = True
                in_permissions = False
                in_env_block = False
                continue

            if line.startswith("permissions:"):
                in_permissions = True
                in_on_block = False
                in_env_block = False
                if WRITE_ALL_PERMISSIONS_PATTERN.search(line):
                    findings.append(
                        WorkflowFinding(
                            kind="write_all_permissions",
                            severity="high",
                            message="permissions: write-all grants excessive workflow access",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if in_permissions and CONTENTS_WRITE_PATTERN.match(line):
                findings.append(
                    WorkflowFinding(
                        kind="contents_write",
                        severity="medium",
                        message="contents: write permission — restrict to jobs that need it",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_on_block and PULL_REQUEST_TARGET_PATTERN.match(line):
                has_pull_request_target = True
                info.triggers.append("pull_request_target")
                findings.append(
                    WorkflowFinding(
                        kind="pull_request_target",
                        severity="high",
                        message=(
                            "pull_request_target runs with base-repo credentials — "
                            "avoid checking out untrusted PR code"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("jobs", "env", "steps", "strategy", "matrix"):
                    in_on_block = False
                if key == "env":
                    in_env_block = True
                    env_indent = len(raw) - len(raw.lstrip())
                elif key != "env":
                    in_env_block = False
                if key == "jobs":
                    in_permissions = False

            if line.startswith("jobs:"):
                in_on_block = False
                in_permissions = False

            if in_on_block and line.startswith("- "):
                trigger = line[2:].strip().rstrip(":")
                if trigger:
                    info.triggers.append(trigger)

            if re.match(r"^\S+:\s*$", line) and not line.startswith("-"):
                job_name = line[:-1].strip()
                if job_name not in ("on", "env", "permissions", "jobs", "name", "concurrency"):
                    if job_name and job_name[0].isalpha():
                        info.jobs.append(job_name)

            if UNPINNED_REF_PATTERN.search(line):
                findings.append(
                    WorkflowFinding(
                        kind="unpinned_action",
                        severity="high",
                        message="action pinned to mutable branch (@main/@master) — pin to a commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MUTABLE_TAG_PATTERN.search(line):
                findings.append(
                    WorkflowFinding(
                        kind="mutable_tag",
                        severity="medium",
                        message="action uses floating major tag (@v1) — pin to full version or SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CHECKOUT_NO_PERSIST_PATTERN.search(line):
                info.uses_checkout = True
                checkout_lines.append((lineno, raw.strip()))

            if PERSIST_CREDENTIALS_TRUE_PATTERN.search(line):
                findings.append(
                    WorkflowFinding(
                        kind="persist_credentials",
                        severity="medium",
                        message="persist-credentials: true can leak tokens to subsequent steps",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env_block and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
                    findings.append(
                        WorkflowFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in env — use GitHub Secrets",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("run:") or " run:" in line:
                if CURL_PIPE_SHELL_PATTERN.search(line):
                    findings.append(
                        WorkflowFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in workflow run step is unsafe",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if SCRIPT_INJECTION_PATTERN.search(line):
                    findings.append(
                        WorkflowFinding(
                            kind="script_injection",
                            severity="high",
                            message=(
                                "github.event context interpolated into run script — "
                                "use env vars with quoting to prevent injection"
                            ),
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if has_pull_request_target and UNSAFE_ENV_CONTEXT_PATTERN.search(line):
                    findings.append(
                        WorkflowFinding(
                            kind="env_context_in_pr_target",
                            severity="medium",
                            message="env context in pull_request_target workflow — validate untrusted input",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        if has_pull_request_target and checkout_lines:
            for lineno, line in checkout_lines:
                findings.append(
                    WorkflowFinding(
                        kind="checkout_with_pr_target",
                        severity="high",
                        message=(
                            "actions/checkout with pull_request_target — "
                            "checkout untrusted code only in isolated jobs"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[WorkflowFinding]:
        """Scan workflow files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[WorkflowFinding] = []
        infos: list[WorkflowInfo] = []
        paths = self.workflows()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = WorkflowStats(
            workflows=len(paths),
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened GitHub Actions workflow template."""
        return """\
# Generated by DevAI WorkflowAnalyzer
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@8d9f9acfe6e514bcd561bc4b96759fba508e4aeb  # v5.3.0
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run tests
        run: python -m pytest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.workflows == 0:
            return "Workflows: none found"
        return (
            f"Workflows: {stats.workflows} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitHub Actions workflow analysis:",
            f"  workflows: {stats.workflows}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            triggers = ", ".join(info.triggers[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.jobs)} job(s), triggers=[{triggers}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
