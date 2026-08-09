"""BitbucketPipelinesAnalyzer — audit Bitbucket Pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BITBUCKET_PIPELINES_NAMES = ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml")

LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)


@dataclass
class BitbucketPipelinesFinding:
    """A security or best-practice issue in a Bitbucket Pipelines config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    step: str = ""
    line: str = ""

    def format(self) -> str:
        step = f" ({self.step})" if self.step else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{step} — {self.message}"


@dataclass
class BitbucketPipelinesInfo:
    """Parsed metadata about a Bitbucket Pipelines file."""

    path: str
    pipelines: list[str] = field(default_factory=list)
    steps: int = 0
    lines: int = 0


@dataclass
class BitbucketPipelinesStats:
    """Aggregate Bitbucket Pipelines analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bitbucket_pipelines_file(path: Path) -> bool:
    return path.name.lower() in BITBUCKET_PIPELINES_NAMES


class BitbucketPipelinesAnalyzer:
    """Audit Bitbucket Pipelines for security risks and CI best practices.

    Scans for unpinned images, hardcoded secrets, curl-pipe-to-shell, privileged
    services, and docker socket mounts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BitbucketPipelinesFinding] | None = None
        self._stats: BitbucketPipelinesStats | None = None
        self._infos: list[BitbucketPipelinesInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bitbucket Pipelines config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_bitbucket_pipelines_file(path):
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
        current_step = ""
        in_script = False
        in_variables = False
        var_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("pipelines:"):
                in_script = False
                in_variables = False
                continue

            if re.match(r"^[a-zA-Z0-9_.-]+:\s*$", line):
                key = line[:-1].strip()
                if key in ("branches", "pull-requests", "tags", "custom", "default"):
                    info.pipelines.append(key)
                if key == "variables":
                    in_variables = True
                    var_indent = len(raw) - len(raw.lstrip())
                elif key != "variables":
                    in_variables = False

            if line.startswith("- step:") or line == "step:":
                info.steps += 1
                in_script = False
                continue

            if line.startswith("name:") and "step" in raw.lower():
                current_step = line.split(":", 1)[1].strip().strip("'\"")

            if line == "script:" or line.startswith("script:"):
                in_script = True
                in_variables = False
                continue

            if in_variables and SECRET_VAR_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > var_indent:
                    findings.append(
                        BitbucketPipelinesFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use Bitbucket secured variables",
                            path=rel,
                            lineno=lineno,
                            step=current_step,
                            line=raw.strip(),
                        )
                    )

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="latest_image",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        step=current_step,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged service enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        step=current_step,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="docker_sock",
                        severity="high",
                        message="docker socket mount grants host-level access",
                        path=rel,
                        lineno=lineno,
                        step=current_step,
                        line=raw.strip(),
                    )
                )

            if in_script or (line.startswith("- ") and "curl" in line.lower()):
                script_line = line[2:].strip() if line.startswith("- ") else line
                if CURL_PIPE_SHELL_PATTERN.search(script_line):
                    findings.append(
                        BitbucketPipelinesFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in script is unsafe",
                            path=rel,
                            lineno=lineno,
                            step=current_step,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[BitbucketPipelinesFinding]:
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BitbucketPipelinesInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.configs == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        return """\
# Generated by DevAI BitbucketPipelinesAnalyzer
image: python:3.12-slim

pipelines:
  default:
    - step:
        name: Test
        caches:
          - pip
        script:
          - pip install -e ".[dev]"
          - python -m pytest

definitions:
  caches:
    pip: ~/.cache/pip
"""

    def summary(self) -> str:
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
        self.analyze()
        stats = self.stats
        lines = [
            "Bitbucket Pipelines analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            pipelines = ", ".join(info.pipelines[:5]) or "default"
            lines.append(f"  - {info.path}: {info.steps} step(s), pipelines=[{pipelines}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
