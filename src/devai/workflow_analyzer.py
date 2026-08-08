"""WorkflowAnalyzer — audit GitHub Actions workflows for CI security issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOW_DIR = ".github/workflows"

UNPINNED_ACTION_PATTERN = re.compile(
    r"uses:\s*['\"]?([^@'\"\s]+)@(main|master|dev|latest)['\"]?\s*$",
    re.IGNORECASE,
)
MISSING_VERSION_ACTION_PATTERN = re.compile(
    r"uses:\s*['\"]?([^@'\"\s/]+/[^@'\"\s/]+)['\"]?\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*[:=]\s*['\"]?[^\s'\"${}]+",
    re.IGNORECASE,
)
WRITE_ALL_PATTERN = re.compile(r"write-all|contents:\s*write", re.IGNORECASE)
PULL_REQUEST_TARGET_PATTERN = re.compile(r"pull_request_target\s*:", re.IGNORECASE)
CHECKOUT_UNTRUSTED_PATTERN = re.compile(
    r"ref:\s*\$\{\{\s*github\.event\.(pull_request|issue)\.",
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
    jobs: int = 0
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


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class WorkflowAnalyzer:
    """Audit GitHub Actions workflows for CI security risks.

    Detects pull_request_target misuse, unpinned actions, secrets in env,
    curl-pipe-to-shell patterns, and overly broad GITHUB_TOKEN permissions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WorkflowFinding] | None = None
        self._stats: WorkflowStats | None = None
        self._infos: list[WorkflowInfo] | None = None

    def workflows(self) -> list[Path]:
        """Return workflow YAML files under .github/workflows."""
        workflow_root = self.root / WORKFLOW_DIR
        if not workflow_root.is_dir():
            return []
        found: list[Path] = []
        for path in sorted(workflow_root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix in (".yml", ".yaml"):
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
        in_permissions = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line.strip():
                continue
            stripped = line.strip()

            if stripped.startswith("on:") or stripped.startswith("on "):
                info.triggers.append("configured")

            if re.match(r"^\s*[\w-]+\s*:", stripped) and "jobs:" not in stripped:
                trigger = stripped.split(":", 1)[0].strip()
                if trigger in (
                    "push",
                    "pull_request",
                    "pull_request_target",
                    "schedule",
                    "workflow_dispatch",
                    "release",
                ):
                    info.triggers.append(trigger)

            if PULL_REQUEST_TARGET_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="pull_request_target",
                        severity="high",
                        message=(
                            "pull_request_target runs with base-repo permissions — "
                            "avoid checking out untrusted PR code"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if stripped.startswith("jobs:"):
                info.jobs += 1

            if "uses:" in stripped and "actions/checkout" in stripped:
                info.uses_checkout = True

            if UNPINNED_ACTION_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="unpinned_action",
                        severity="medium",
                        message="action pinned to a moving branch (@main/@master) — pin a version tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
            elif MISSING_VERSION_ACTION_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="missing_action_version",
                        severity="medium",
                        message="action reference missing @version — pin to a specific release",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(stripped):
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

            if SECRET_ENV_PATTERN.search(stripped):
                if "${{" not in stripped and "secrets." not in stripped:
                    findings.append(
                        WorkflowFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret literal in workflow env — use GitHub secrets",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if stripped.startswith("permissions:"):
                in_permissions = True
            elif in_permissions and WRITE_ALL_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="broad_permissions",
                        severity="medium",
                        message="overly broad GITHUB_TOKEN permissions — use least privilege",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
            elif in_permissions and stripped and not stripped.startswith(" "):
                in_permissions = False

            if CHECKOUT_UNTRUSTED_PATTERN.search(stripped):
                findings.append(
                    WorkflowFinding(
                        kind="untrusted_checkout_ref",
                        severity="high",
                        message="checkout ref from PR/issue event can enable code injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
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
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ".[dev]"
      - run: python -m pytest
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
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Workflow analysis:",
            f"  workflows: {stats.workflows}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {info.jobs} job block(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
