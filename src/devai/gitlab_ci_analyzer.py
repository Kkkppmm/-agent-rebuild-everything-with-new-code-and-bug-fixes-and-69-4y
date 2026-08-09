"""GitLabCIAnalyzer — audit GitLab CI/CD pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
)

LATEST_IMAGE_PATTERN = re.compile(r"^\s*image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
UNPINNED_REF_PATTERN = re.compile(
    r"^\s*ref:\s*(main|master|HEAD|develop|dev|nightly|latest)\s*$",
    re.IGNORECASE,
)
MUTABLE_TAG_REF_PATTERN = re.compile(r"^\s*ref:\s*v\d+\s*$", re.IGNORECASE)
UNPINNED_COMPONENT_PATTERN = re.compile(
    r"component:\s*[^\s]+@(main|master|latest)\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?CI_(MERGE_REQUEST|COMMIT|PIPELINE)[^}\s]*\}?",
    re.IGNORECASE,
)
UNMASKED_SECRET_VAR_PATTERN = re.compile(
    r"^\s*(masked|protected):\s*false\b",
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
    job: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        job = f" ({self.job})" if self.job else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{job} — {self.message}"


@dataclass
class GitLabCIJobInfo:
    """Parsed metadata about a GitLab CI job."""

    name: str
    stage: str | None = None
    has_image: bool = False


@dataclass
class GitLabCIInfo:
    """Parsed metadata about a GitLab CI config file."""

    path: str
    jobs: list[GitLabCIJobInfo] = field(default_factory=list)
    includes: int = 0
    lines: int = 0


@dataclass
class GitLabCIStats:
    """Aggregate GitLab CI analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitlab_ci_file(path: Path) -> bool:
    name = path.name.lower()
    if name in CONFIG_NAMES:
        return True
    return name.endswith(".gitlab-ci.yml") or name.endswith(".gitlab-ci.yaml")


class GitLabCIAnalyzer:
    """Audit GitLab CI/CD pipelines for security risks and CI best practices.

    Scans for unpinned includes, :latest images, secrets in variables,
    privileged services, curl-pipe-to-shell scripts, and unsafe CI variable
    interpolation in job scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return GitLab CI config file paths found in the project."""
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
        current_job = ""
        in_variables = False
        var_indent = 0
        var_has_secret_name = False
        in_script = False
        script_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if indent == 0 and re.match(r"^[a-zA-Z0-9_.-]+:\s*$", line):
                key = line[:-1].strip()
                if key not in ("include", "stages", "variables", "workflow", "default"):
                    current_job = key
                    info.jobs.append(GitLabCIJobInfo(name=key))
                    in_variables = False
                    in_script = False

            if line.startswith("include:") or line == "- include":
                info.includes += 1

            if line == "variables:" or line.startswith("variables:"):
                in_variables = True
                var_indent = indent
                var_has_secret_name = False
                in_script = False
                continue

            if line == "script:" or line.startswith("script:"):
                in_script = True
                script_indent = indent
                in_variables = False
                continue

            if in_variables and indent <= var_indent and not line.startswith("-"):
                in_variables = False
                var_has_secret_name = False

            if in_script and indent <= script_indent and not line.startswith("-"):
                in_script = False

            if LATEST_IMAGE_PATTERN.match(line):
                job_info = next((j for j in info.jobs if j.name == current_job), None)
                if job_info:
                    job_info.has_image = True
                findings.append(
                    GitLabCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_REF_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="unpinned_ref",
                        severity="high",
                        message="include/component ref pinned to mutable branch — use a tag or SHA",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if MUTABLE_TAG_REF_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="mutable_tag_ref",
                        severity="medium",
                        message="ref uses floating major tag (v1) — pin to full version or SHA",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_COMPONENT_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="unpinned_component",
                        severity="high",
                        message="CI component pinned to mutable branch — pin to a version",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="privileged_service",
                        severity="high",
                        message="privileged: true grants full host access in CI service",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if in_variables and SECRET_VAR_PATTERN.search(line):
                var_has_secret_name = True

            if in_variables and var_has_secret_name and UNMASKED_SECRET_VAR_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="unmasked_secret_var",
                        severity="high",
                        message="sensitive variable not masked/protected — enable masked and protected",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if in_variables and var_has_secret_name and ":" in line and not line.startswith("-"):
                if SECRET_VAR_PATTERN.search(line) and re.search(r":\s*['\"][^'\"]{4,}", line):
                    findings.append(
                        GitLabCIFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use GitLab CI/CD variables",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )
                    var_has_secret_name = False

            check_line = line.lstrip("- ").strip()
            if CURL_PIPE_SHELL_PATTERN.search(check_line):
                findings.append(
                    GitLabCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in CI script is unsafe",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if in_script and SCRIPT_INJECTION_PATTERN.search(check_line):
                if not re.search(r"['\"].*\$CI_", check_line):
                    findings.append(
                        GitLabCIFinding(
                            kind="script_injection",
                            severity="high",
                            message=(
                                "CI variable interpolated in script without quoting — "
                                "wrap in quotes to prevent injection"
                            ),
                            path=rel,
                            lineno=lineno,
                            job=current_job,
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
        paths = self.config_files()

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
            config_files=len(paths),
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
        if stats.config_files == 0:
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
        """Scaffold a hardened GitLab CI pipeline template."""
        return """\
# Generated by DevAI GitLabCIAnalyzer
stages:
  - test

variables:
  PIP_DISABLE_PIP_VERSION_CHECK: "1"

test:
  stage: test
  image: python:3.12-slim
  script:
    - pip install -e ".[dev]"
    - python -m pytest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "GitLab CI: no config found"
        return (
            f"GitLab CI: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI/CD pipeline analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s), {info.includes} include(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
