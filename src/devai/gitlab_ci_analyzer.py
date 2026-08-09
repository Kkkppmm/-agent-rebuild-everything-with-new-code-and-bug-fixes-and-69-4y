"""GitLabCIAnalyzer — audit GitLab CI/CD pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GITLAB_CI_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
UNPINNED_REF_PATTERN = re.compile(
    r"include:\s*\n\s*-\s*(remote|project|local):\s*[^\s@]+@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?CI_[A-Z0-9_]+\}?|\$\{?GITLAB_USER_INPUT\}?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(r"network_mode:\s*['\"]?host['\"]?", re.IGNORECASE)
PLAIN_SECRET_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(PASSWORD|SECRET|TOKEN|API_KEY)['\"]?\s*:\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)


@dataclass
class GitLabCIFinding:
    """A security or best-practice issue in a GitLab CI file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    job: str = ""
    line: str = ""

    def format(self) -> str:
        job = f" ({self.job})" if self.job else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{job} — {self.message}"


@dataclass
class GitLabCIInfo:
    """Parsed metadata about a GitLab CI file."""

    path: str
    jobs: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    has_include: bool = False
    lines: int = 0


@dataclass
class GitLabCIStats:
    """Aggregate GitLab CI analysis statistics."""

    pipelines: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitlab_ci_file(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_NAMES


class GitLabCIAnalyzer:
    """Audit GitLab CI/CD pipelines for hardcoded secrets, privileged services, and unsafe scripts."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def pipeline_files(self) -> list[Path]:
        """Return GitLab CI file paths found in the project."""
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if indent == 0 and line.startswith("stages:"):
                continue
            if indent == 0 and line.startswith("include:"):
                info.has_include = True
                if UNPINNED_REF_PATTERN.search(raw):
                    findings.append(
                        GitLabCIFinding(
                            kind="unpinned_include",
                            severity="medium",
                            message="CI include references unpinned branch (main/master/dev)",
                            path=rel,
                            lineno=lineno,
                            line=line[:120],
                        )
                    )
                continue

            if indent == 0 and line.endswith(":") and not line.startswith(("-", "include", "stages", "variables", "workflow")):
                current_job = line[:-1]
                info.jobs.append(current_job)
                continue

            if line == "variables:" or line.startswith("variables:"):
                in_variables = True
                var_indent = indent
                continue

            if in_variables and indent <= var_indent and not line.startswith("-"):
                in_variables = False

            if in_variables and SECRET_VAR_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="secret_in_variables",
                        severity="high",
                        message="Potential secret hardcoded in CI variables block",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if PLAIN_SECRET_PATTERN.search(raw):
                findings.append(
                    GitLabCIFinding(
                        kind="plain_secret",
                        severity="high",
                        message="Plain-text secret value in CI configuration",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="Docker service runs in privileged mode",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="Docker socket mounted — grants host-level container control",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="host_network",
                        severity="high",
                        message="Container uses host networking",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="Remote script downloaded and piped to shell",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=line[:120],
                    )
                )

            if line.startswith("- ") or line.startswith("script:") or "script:" in line:
                if SCRIPT_INJECTION_PATTERN.search(line) and "echo" in line.lower():
                    findings.append(
                        GitLabCIFinding(
                            kind="script_injection",
                            severity="medium",
                            message="CI variable interpolated directly in script — validate input",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=line[:120],
                        )
                    )

        return findings, info

    def analyze(self) -> list[GitLabCIFinding]:
        """Scan all GitLab CI files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitLabCIFinding] = []
        infos: list[GitLabCIInfo] = []
        paths = self.pipeline_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = GitLabCIStats(
            pipelines=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitLabCIStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitLabCIInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "GitLab CI: none found"
        return (
            f"GitLab CI: {stats.pipelines} pipeline(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
