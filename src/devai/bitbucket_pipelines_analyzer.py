"""BitbucketPipelinesAnalyzer — audit Bitbucket Pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BITBUCKET_PIPELINE_NAMES = ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml")
BITBUCKET_DIRS = ("bitbucket", "ci", ".bitbucket")

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
    r"(?:script|after-script):\s*.*\$\{?[A-Z_]+\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNTRUSTED_PR_TRIGGER_PATTERN = re.compile(
    r"pull-requests:\s*\n\s*'\*\*':",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
DOCKER_SERVICE_PATTERN = re.compile(
    r"services:\s*\n\s*-\s*docker",
    re.IGNORECASE,
)
SIZE_2X_PATTERN = re.compile(r"size:\s*2x\b", re.IGNORECASE)
ALLOW_FAILURE_PATTERN = re.compile(
    r"^\s*-\s*step:\s*$",
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
    if lower in BITBUCKET_PIPELINE_NAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(BITBUCKET_DIRS) and lower.endswith((".yml", ".yaml")):
        if "bitbucket" in lower or "pipeline" in lower:
            return True
    return False


class BitbucketPipelinesAnalyzer:
    """Audit Bitbucket Pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `bitbucket-pipelines.yml` for curl-pipe-to-shell, privileged services,
    hardcoded credentials, and untrusted pull-request pipeline triggers.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BitbucketPipelinesFinding] | None = None
        self._stats: BitbucketPipelinesStats | None = None
        self._infos: list[BitbucketPipelinesInfo] | None = None

    def files(self) -> list[Path]:
        """Return Bitbucket Pipelines files found in the project."""
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
        in_security_step = False
        has_pr_trigger = False
        in_variables = False
        variables_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^pipelines\s*:", line, re.IGNORECASE):
                continue

            if re.match(r"^\s{2}(default|branches|pull-requests|tags|custom)\s*:", raw, re.IGNORECASE):
                pipeline_name = raw.strip().split(":")[0].strip()
                info.pipelines.append(pipeline_name)
                if pipeline_name == "pull-requests":
                    has_pr_trigger = True

            if re.match(r"^\s*-\s*step\s*:", line, re.IGNORECASE):
                info.steps += 1
                in_security_step = False

            if re.match(r"^\s*name:\s*.*(?:security|audit|scan|sast|dast)", line, re.IGNORECASE):
                in_security_step = True

            if re.match(r"^\s*script\s*:", line, re.IGNORECASE):
                in_script = True
                script_indent = len(raw) - len(raw.lstrip())
                continue

            if re.match(r"^\s*variables\s*:", line, re.IGNORECASE):
                in_variables = True
                variables_indent = len(raw) - len(raw.lstrip())
                continue

            if in_variables:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= variables_indent and not line.startswith("-"):
                    in_variables = False
                elif HARDCODED_SECRET_PATTERN.search(line):
                    findings.append(
                        BitbucketPipelinesFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded credential in variables — use Bitbucket repository variables",
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
                                message="unquoted variable in script — validate untrusted pull-request input",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if SUDO_PATTERN.search(line):
                        findings.append(
                            BitbucketPipelinesFinding(
                                kind="sudo_usage",
                                severity="medium",
                                message="sudo in pipeline script — use service containers instead of elevated privileges",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if HARDCODED_SECRET_PATTERN.search(line) and not in_variables:
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Bitbucket repository or deployment variables",
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

            if DOCKER_SERVICE_PATTERN.search(line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="docker_service",
                        severity="medium",
                        message="Docker service enabled — restrict to trusted branches and validate image sources",
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

            if has_pr_trigger and re.search(r"BITBUCKET_PR_ID|BITBUCKET_BRANCH", line):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="pr_variable_in_script",
                        severity="medium",
                        message="PR variables in pull-request pipeline — restrict secrets for fork PRs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(r"trigger:\s*manual", line, re.IGNORECASE):
                findings.append(
                    BitbucketPipelinesFinding(
                        kind="manual_security_step",
                        severity="medium",
                        message="security step requires manual trigger — automate security scans on every PR",
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

  pull-requests:
    '**':
      - step:
          name: Test
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
            pnames = ", ".join(info.pipelines[:5]) or "none"
            lines.append(
                f"  - {info.path}: {info.steps} step(s), pipelines=[{pnames}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
