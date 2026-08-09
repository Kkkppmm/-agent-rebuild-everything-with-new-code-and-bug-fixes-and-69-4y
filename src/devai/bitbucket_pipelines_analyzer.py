"""BitbucketPipelinesAnalyzer — audit Bitbucket Pipelines configs for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINES_NAMES = ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml")

UNPINNED_PIPE_PATTERN = re.compile(
    r"pipe:\s*[^\s@]+@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
MUTABLE_PIPE_TAG_PATTERN = re.compile(
    r"pipe:\s*[^\s@]+@v\d+\b(?![.\d])",
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
PRIVILEGED_SERVICE_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)


@dataclass
class BitbucketPipelinesFinding:
    """A security or best-practice issue in a Bitbucket Pipelines config."""

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
class BitbucketPipelinesInfo:
    """Parsed metadata about a Bitbucket Pipelines config."""

    path: str
    pipelines: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class BitbucketPipelinesStats:
    """Aggregate Bitbucket Pipelines analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pipelines_file(path: Path) -> bool:
    return path.name.lower() in PIPELINES_NAMES


class BitbucketPipelinesAnalyzer:
    """Audit Bitbucket Pipelines configs for security risks and CI best practices.

    Scans for unpinned pipes, secrets in variables, privileged services,
    docker.sock mounts, and curl-pipe-to-shell patterns in script steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BitbucketPipelinesFinding] | None = None
        self._stats: BitbucketPipelinesStats | None = None
        self._infos: list[BitbucketPipelinesInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bitbucket Pipelines config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pipelines_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BitbucketPipelinesFinding], BitbucketPipelinesInfo]:
        findings: list[BitbucketPipelinesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BitbucketPipelinesInfo(path=rel)

        info = BitbucketPipelinesInfo(path=rel, lines=len(raw_lines))
        in_pipelines = False
        in_variables = False
        var_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if line == "pipelines:" or line.startswith("pipelines:"):
                in_pipelines = True
                in_variables = False
                continue

            if line.startswith("variables:") or line == "variables:":
                in_variables = True
                var_indent = indent
                continue

            if in_variables and indent <= var_indent and not line.startswith("-"):
                in_variables = False

            if in_pipelines and indent == 2 and line.endswith(":") and not line.startswith("-"):
                pipeline_name = line[:-1].strip()
                if pipeline_name not in ("default", "branches", "pull-requests", "custom"):
                    info.pipelines.append(pipeline_name)

            if UNPINNED_PIPE_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="unpinned_pipe",
                        severity="high",
                        message="pipe pinned to mutable branch (@main/@latest) — pin to a version tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MUTABLE_PIPE_TAG_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="mutable_pipe_tag",
                        severity="medium",
                        message="pipe uses floating major tag (@v1) — pin to full version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_variables and SECRET_VAR_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="secret_in_variables",
                        severity="high",
                        message="potential secret in variables — use Bitbucket secured variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_SERVICE_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="privileged_service",
                        severity="high",
                        message="privileged: true grants full host access in pipeline service",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="docker.sock mount allows container escape to host",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in script step is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[BitbucketPipelinesFinding]:
        """Scan Bitbucket Pipelines configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BitbucketPipelinesFinding] = []
        infos: list[BitbucketPipelinesInfo] = []
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
        self._stats = BitbucketPipelinesStats(
            configs=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BitbucketPipelinesStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BitbucketPipelinesInfo]:
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
        """Scaffold a hardened Bitbucket Pipelines config template."""
        return """\
# Generated by DevAI BitbucketPipelinesAnalyzer
image: python:3.12.7-slim

pipelines:
  default:
    - step:
        name: Test
        caches:
          - pip
        script:
          - pip install -e ".[dev]"
          - python -m pytest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bitbucket Pipelines: none found"
        return (
            f"Bitbucket Pipelines: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bitbucket Pipelines analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.pipelines)} pipeline(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
