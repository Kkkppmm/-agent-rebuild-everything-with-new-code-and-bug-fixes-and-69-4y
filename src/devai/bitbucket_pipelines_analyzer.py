"""BitbucketPipelinesAnalyzer — audit Bitbucket Pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BITBUCKET_NAMES = ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml")
BITBUCKET_DIRS = (".bitbucket", "bitbucket", "ci")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"image:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_SERVICE_PATTERN = re.compile(
    r"privileged:\s*true\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:- |\s)(?:script|after-script|before-script):\s*.*\$\{?[A-Z_]+\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
ALLOW_FAILURE_SECURITY_PATTERN = re.compile(
    r"^\s*-\s*step:\s*$|^\s*name:\s*.*(?:security|audit|scan|sast|dast)",
    re.IGNORECASE,
)


@dataclass
class BitbucketPipelinesFinding:
    """A security or best-practice issue in a Bitbucket Pipelines file."""

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
    """Parsed metadata about a Bitbucket Pipelines file."""

    path: str
    pipelines: list[str] = field(default_factory=list)
    steps: int = 0
    lines: int = 0


@dataclass
class BitbucketPipelinesStats:
    """Aggregate Bitbucket Pipelines analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bitbucket_pipelines_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in BITBUCKET_NAMES:
        return True
    if lower.endswith((".bitbucket-pipelines.yml", ".bitbucket-pipelines.yaml")):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(BITBUCKET_DIRS) and lower.endswith((".yml", ".yaml")):
        if "pipeline" in lower or "bitbucket" in lower:
            return True
    return False


class BitbucketPipelinesAnalyzer:
    """Audit Bitbucket Pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans ``bitbucket-pipelines.yml`` for curl-pipe-to-shell, privileged services,
    floating image tags, script injection via unquoted variables, and hardcoded credentials.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BitbucketPipelinesFinding] | None = None
        self._stats: BitbucketPipelinesStats | None = None
        self._infos: list[BitbucketPipelinesInfo] | None = None

    def files(self) -> list[Path]:
        """Return Bitbucket Pipelines file paths found in the project."""
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
        in_script = False
        script_indent = 0
        current_pipeline: str | None = None
        in_security_step = False
        step_allow_failure = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("pipelines:"):
                in_script = False
                continue

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("default", "branches", "pull-requests", "tags", "custom"):
                    current_pipeline = key
                    if key not in info.pipelines:
                        info.pipelines.append(key)
                    in_script = False
                    continue
                if key in ("script", "after-script", "before-script"):
                    in_script = True
                    script_indent = len(raw) - len(raw.lstrip())
                    continue
                if key == "step":
                    info.steps += 1
                    in_security_step = False
                    step_allow_failure = False

            if line.startswith("name:") and any(
                token in line.lower() for token in ("security", "audit", "scan", "sast", "dast")
            ):
                in_security_step = True

            if "allow-failure: true" in line.lower() or "allow_failure: true" in line.lower():
                step_allow_failure = True

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="potential secret hardcoded in pipeline — use Bitbucket secured variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
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
                        message="privileged: true in service — avoid privileged containers",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_script:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= script_indent and not line.startswith("-"):
                    in_script = False
                else:
                    if CURL_PIPE_SHELL_PATTERN.search(line):
                        findings.append(
                            BitbucketPipelinesFinding(
                                kind="curl_pipe_shell",
                                severity="high",
                                message="piping curl/wget to shell in pipeline script is unsafe",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if SCRIPT_INJECTION_PATTERN.search(line):
                        findings.append(
                            BitbucketPipelinesFinding(
                                kind="script_injection",
                                severity="high",
                                message=(
                                    "unquoted pipeline variable in script — use double quotes "
                                    "and validate untrusted input"
                                ),
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if line.startswith("- ") and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in pipeline script is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if step_allow_failure and in_security_step and "script:" in line.lower():
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="security_allow_failure",
                        severity="medium",
                        message="allow-failure on security step — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and "http://" in line.lower():
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[BitbucketPipelinesFinding]:
        """Scan Bitbucket Pipelines files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BitbucketPipelinesFinding] = []
        infos: list[BitbucketPipelinesInfo] = []
        paths = self.files()

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
            pipelines=len(paths),
            files=len(paths),
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
        """Return parsed pipeline metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no pipelines)."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
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
        """Scaffold a hardened Bitbucket Pipelines template."""
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

    - step:
        name: Security scan
        script:
          - pip install devai
          - devai security-scan .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Bitbucket Pipelines: none found"
        return (
            f"Bitbucket Pipelines: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bitbucket Pipelines analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            pipelines = ", ".join(info.pipelines[:5]) or "none"
            lines.append(
                f"  - {info.path}: {info.steps} step(s), pipelines=[{pipelines}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
