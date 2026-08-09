"""GitLabCIAnalyzer — audit GitLab CI/CD pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GITLAB_CI_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"image:\s*[^\s:]+@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
REMOTE_INCLUDE_PATTERN = re.compile(
    r"include:\s*\n\s*-\s*remote:\s*['\"]https?://",
    re.IGNORECASE,
)
INSECURE_ALLOW_FAILURE_PATTERN = re.compile(
    r"allow_failure:\s*true\b.*security|audit|scan",
    re.IGNORECASE,
)


@dataclass
class GitLabCIFinding:
    """A security or best-practice issue in a GitLab CI config."""

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
class GitLabCIInfo:
    """Parsed metadata about a GitLab CI config."""

    path: str
    jobs: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class GitLabCIStats:
    """Aggregate GitLab CI analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitlab_ci_file(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_NAMES


class GitLabCIAnalyzer:
    """Audit GitLab CI/CD configs for security risks and pipeline best practices.

    Scans for unpinned images, secrets in variables, privileged Docker services,
    remote include from HTTP(S), and curl-pipe-to-shell patterns in script steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return GitLab CI config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_gitlab_ci_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GitLabCIFinding], GitLabCIInfo]:
        findings: list[GitLabCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitLabCIInfo(path=rel)

        info = GitLabCIInfo(path=rel, lines=len(raw_lines))
        in_variables = False
        var_indent = 0
        in_stages = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if line == "stages:" or line.startswith("stages:"):
                in_stages = True
                in_variables = False
                continue

            if in_stages and line.startswith("- "):
                stage = line[2:].strip()
                if stage:
                    info.stages.append(stage)

            if line.startswith("variables:") or line == "variables:":
                in_variables = True
                var_indent = indent
                continue

            if in_variables and indent <= var_indent and not line.startswith("-"):
                in_variables = False

            if indent == 0 and line.endswith(":") and not line.startswith(("include", "stages", "variables", "workflow")):
                job_name = line[:-1].strip()
                if job_name and job_name[0].isalpha():
                    info.jobs.append(job_name)

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="unpinned_image",
                        severity="high",
                        message="image pinned to mutable branch (@main/@latest) — pin to a version tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_variables and SECRET_VAR_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="secret_in_variables",
                        severity="high",
                        message="potential secret in variables — use GitLab CI/CD variables (masked)",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged: true grants full host access in Docker service",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if "remote:" in line.lower() and re.search(r"https?://", line):
                findings.append(
                    GitLabCIFinding(
                        kind="remote_include",
                        severity="medium",
                        message="remote include from URL — verify source integrity and pin versions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in script step is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[GitLabCIFinding]:
        """Scan GitLab CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitLabCIFinding] = []
        infos: list[GitLabCIInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = GitLabCIStats(
            configs=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitLabCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitLabCIInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
        """Scaffold a hardened GitLab CI config template."""
        return """\
# Generated by DevAI GitLabCIAnalyzer
stages:
  - test

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

test:
  stage: test
  image: python:3.12.7-slim
  cache:
    paths:
      - .cache/pip
  script:
    - pip install -e ".[dev]"
    - python -m pytest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "GitLab CI: none found"
        return (
            f"GitLab CI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI/CD analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            jobs = ", ".join(info.jobs[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s), jobs=[{jobs}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
