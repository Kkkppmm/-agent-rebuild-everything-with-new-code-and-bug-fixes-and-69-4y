"""GitLabCIAnalyzer — audit GitLab CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GITLAB_CI_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

LATEST_IMAGE_PATTERN = re.compile(
    r"image:\s*[^\s:]+:latest\b",
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
PRIVILEGED_RUNNER_PATTERN = re.compile(
    r"privileged:\s*true\b",
    re.IGNORECASE,
)
ALLOW_FAILURE_SECRET_PATTERN = re.compile(
    r"^\s*-\s*when:\s*always\b",
    re.IGNORECASE,
)
UNPROTECTED_VAR_PATTERN = re.compile(
    r"^\s*\w+:\s*['\"]?[^'\"]+['\"]?\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?CI_(COMMIT|MERGE_REQUEST|PIPELINE|JOB)[^}]*\}?",
    re.IGNORECASE,
)
INSECURE_ARTIFACT_PATTERN = re.compile(
    r"artifacts:\s*$|when:\s*always",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
SERVICES_LATEST_PATTERN = re.compile(
    r"services:\s*$|^\s*-\s*name:\s*[^\s]+:latest\b",
    re.IGNORECASE,
)
UNPINNED_REF_PATTERN = re.compile(
    r"include:\s*$|ref:\s*(main|master|dev|latest)\b",
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
    stage: str = ""
    image: str = ""
    has_script: bool = False


@dataclass
class GitLabCIInfo:
    """Parsed metadata about a GitLab CI config file."""

    path: str
    stages: list[str] = field(default_factory=list)
    jobs: list[GitLabCIJobInfo] = field(default_factory=list)
    includes: int = 0
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
    """Audit GitLab CI configs for security risks and CI best practices.

    Scans for unpinned images, secrets in variables, privileged runners,
    curl-pipe-to-shell patterns, script injection via CI variables, and
    insecure artifact exposure.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def configs(self) -> list[Path]:
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
        in_script = False
        reserved_keys = {
            "stages",
            "variables",
            "include",
            "image",
            "services",
            "before_script",
            "after_script",
            "cache",
            "default",
            "workflow",
        }

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("stages:"):
                in_variables = False
                in_script = False
                continue

            if line.startswith("- ") and not in_script and not in_variables:
                stage = line[2:].strip()
                if stage and not stage.endswith(":"):
                    info.stages.append(stage)

            if line.startswith("include:"):
                info.includes += 1
                if UNPINNED_REF_PATTERN.search(line):
                    findings.append(
                        GitLabCIFinding(
                            kind="unpinned_include",
                            severity="high",
                            message="include uses mutable ref (@main/@latest) — pin to a tag or commit",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if "ref:" in line.lower() and UNPINNED_REF_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="unpinned_include_ref",
                        severity="high",
                        message="include ref points to mutable branch — pin to a tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.match(r"^\S+:\s*$", line) and not line.startswith("-"):
                key = line[:-1].strip()
                if key not in reserved_keys and not key.startswith("."):
                    current_job = key
                    info.jobs.append(GitLabCIJobInfo(name=key))
                    in_script = False
                    in_variables = False

            if line.startswith("variables:"):
                in_variables = True
                var_indent = len(raw) - len(raw.lstrip())
                in_script = False
                continue

            if in_variables and SECRET_VAR_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > var_indent:
                    findings.append(
                        GitLabCIFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use GitLab CI/CD masked variables",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("script:") or line == "before_script:" or line == "after_script:":
                in_script = True
                in_variables = False
                continue

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("artifacts", "cache", "rules", "needs", "extends", "services"):
                    in_script = False
                if key not in ("variables", "script", "before_script", "after_script"):
                    if key in reserved_keys:
                        in_variables = key == "variables"

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if SERVICES_LATEST_PATTERN.search(line) and ":latest" in line.lower():
                findings.append(
                    GitLabCIFinding(
                        kind="latest_service_image",
                        severity="medium",
                        message="service image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_RUNNER_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="privileged_runner",
                        severity="high",
                        message="privileged: true grants full host access to the job container",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="mounting /var/run/docker.sock grants host Docker access",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if in_script or line.startswith("- "):
                script_text = line
                if CURL_PIPE_SHELL_PATTERN.search(script_text):
                    findings.append(
                        GitLabCIFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in script is unsafe",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )
                if SCRIPT_INJECTION_PATTERN.search(script_text) and "$(" in script_text:
                    findings.append(
                        GitLabCIFinding(
                            kind="script_injection",
                            severity="medium",
                            message="CI variable interpolated in script — quote variables to prevent injection",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )

            if INSECURE_ARTIFACT_PATTERN.search(line) and "artifacts" in line.lower():
                pass  # handled via when: always below

            if line.startswith("when:") and "always" in line.lower():
                findings.append(
                    GitLabCIFinding(
                        kind="artifacts_always",
                        severity="low",
                        message="artifacts collected on failure/success always — restrict artifact scope",
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
        """Return parsed GitLab CI metadata."""
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
  image: python:3.12.7-slim-bookworm
  before_script:
    - pip install -e ".[dev]"
  script:
    - python -m pytest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
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
            "GitLab CI config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            jobs = ", ".join(j.name for j in info.jobs[:5]) or "none"
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.jobs)} job(s), stages=[{stages}], jobs=[{jobs}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
