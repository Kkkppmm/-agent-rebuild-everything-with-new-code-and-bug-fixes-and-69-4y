"""CodefreshAnalyzer — audit Codefresh pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CODEFRESH_FILENAMES = ("codefresh.yml", "codefresh.yaml", ".codefresh.yml", ".codefresh.yaml")
CODEFRESH_DIRS = (".codefresh", "codefresh", "ci")

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
    r"(?:image|docker):\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"^\s*privileged\s*:\s*true\s*$",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*network_mode\s*:\s*host\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?\s*CF_(?:BRANCH|PULL_REQUEST|PULL_REQUEST_NUMBER|COMMIT_SHA|SHORT_SHA|REPO_NAME|AUTHOR|TAG)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"^\s*-\s*/(?:etc/passwd|etc/shadow|root|home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"^\s*user\s*:\s*root\s*$",
    re.IGNORECASE,
)
FAIL_FAST_DISABLED_PATTERN = re.compile(
    r"^\s*fail_fast\s*:\s*false\s*$",
    re.IGNORECASE,
)
UNENCRYPTED_EXPORT_PATTERN = re.compile(
    r"^\s*cf_export_variable\s*:\s*[^\"'\s]+",
    re.IGNORECASE,
)
BROAD_WHEN_PATTERN = re.compile(
    r"^\s*when\s*:\s*\{\s*branch\s*:\s*[\"']?\*[\"']?\s*\}",
    re.IGNORECASE,
)


@dataclass
class CodefreshFinding:
    """A security or best-practice issue in a Codefresh pipeline."""

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
class CodefreshInfo:
    """Parsed metadata about a Codefresh pipeline file."""

    path: str
    stages: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CodefreshStats:
    """Aggregate Codefresh analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_codefresh_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CODEFRESH_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(CODEFRESH_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    if lower.endswith(".codefresh.yml") or lower.endswith(".codefresh.yaml"):
        return True
    return False


class CodefreshAnalyzer:
    """Audit Codefresh pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `codefresh.yml` for curl-pipe-to-shell, privileged containers, host networking,
    CF_* variable injection, and secrets in environment blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CodefreshFinding] | None = None
        self._stats: CodefreshStats | None = None
        self._infos: list[CodefreshInfo] | None = None

    def files(self) -> list[Path]:
        """Return Codefresh pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_codefresh_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CodefreshFinding], CodefreshInfo]:
        findings: list[CodefreshFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CodefreshInfo(path=rel)

        info = CodefreshInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_step = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            stage_match = re.match(r"^\s*-\s*([a-zA-Z0-9_-]+)\s*$", raw)
            if stage_match and "stages:" in "\n".join(raw_lines[:lineno]):
                info.stages.append(stage_match.group(1))

            step_match = re.match(r"^\s*([a-zA-Z0-9_-]+):\s*$", raw)
            if step_match and not raw.strip().endswith(":"):
                pass
            elif re.match(r"^\s*[a-zA-Z0-9_-]+:\s*$", raw) and "steps:" in "\n".join(
                raw_lines[max(0, lineno - 5):lineno]
            ):
                current_step = raw.strip().rstrip(":")
                info.steps.append(current_step)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(current_step))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Codefresh encrypted variables or integrations",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    CodefreshFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    CodefreshFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode bypasses container network isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="script_injection",
                        severity="medium",
                        message="CF_* variable interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BROAD_WHEN_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="broad_when_branch",
                        severity="medium",
                        message="when branch matches all branches — restrict deploy steps to protected branches",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path mounted into container — avoid mounting credentials or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CodefreshFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.match(line):
                findings.append(
                    CodefreshFinding(
                        kind="root_user",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNENCRYPTED_EXPORT_PATTERN.match(line):
                findings.append(
                    CodefreshFinding(
                        kind="unencrypted_export",
                        severity="medium",
                        message="cf_export_variable without encryption — use encrypted exports for secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FAIL_FAST_DISABLED_PATTERN.match(line) and in_security_step:
                findings.append(
                    CodefreshFinding(
                        kind="security_fail_fast_disabled",
                        severity="medium",
                        message="security step disables fail_fast — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[CodefreshFinding]:
        """Scan Codefresh pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CodefreshFinding] = []
        infos: list[CodefreshInfo] = []
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
        self._stats = CodefreshStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CodefreshStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CodefreshInfo]:
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
        """Scaffold a hardened Codefresh pipeline template."""
        return """\
# Generated by DevAI CodefreshAnalyzer
version: "1.0"
stages:
  - test
  - security

steps:
  test:
    stage: test
    title: Run tests
    image: python:3.12-slim
    commands:
      - pip install -e ".[dev]"
      - python -m pytest

  security_scan:
    stage: security
    title: Security scan
    image: python:3.12-slim
    commands:
      - pip install devai
      - devai security-scan .
    when:
      branch:
        - main
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Codefresh: none found"
        return (
            f"Codefresh: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Codefresh pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            steps = ", ".join(info.steps[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.steps)} step(s), steps=[{steps}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
