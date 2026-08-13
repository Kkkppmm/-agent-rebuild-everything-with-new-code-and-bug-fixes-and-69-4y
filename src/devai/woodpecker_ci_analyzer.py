"""WoodpeckerCIAnalyzer — audit Woodpecker CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

WOODPECKER_FILENAMES = (".woodpecker.yml", ".woodpecker.yaml", "woodpecker.yml", "woodpecker.yaml")
WOODPECKER_DIRS = (".woodpecker", "woodpecker", "ci")

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
    r"\$\{?\s*WOODPECKER_(?:PULL_REQUEST|COMMIT|BRANCH|REPO|SOURCE_BRANCH|TAG|AUTHOR)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*([a-z0-9_.-]+/[a-z0-9_.-]+)\s*$",
    re.IGNORECASE,
)
FLOATING_PLUGIN_TAG_PATTERN = re.compile(
    r"^\s*tag\s*:\s*(?:latest|master|main|develop)\s*$",
    re.IGNORECASE,
)
TRUSTED_PATTERN = re.compile(
    r"^\s*trusted\s*:\s*true\s*$",
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
DISABLE_TLS_PATTERN = re.compile(
    r"^\s*WOODPECKER_(?:NETRC|REGISTRY)_?(?:PASSWORD|TOKEN)\s*:\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"^\s*user\s*:\s*root\s*$",
    re.IGNORECASE,
)
UNSAFE_WHEN_PATTERN = re.compile(
    r"^\s*(?:when\s*:.*\$\{?\s*WOODPECKER_(?:PULL_REQUEST|COMMIT|BRANCH)|"
    r"(?:branch|tag)\s*:\s*\$?\{?\s*WOODPECKER_(?:PULL_REQUEST|COMMIT|BRANCH|TAG))",
    re.IGNORECASE,
)


@dataclass
class WoodpeckerCIFinding:
    """A security or best-practice issue in a Woodpecker CI pipeline."""

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
class WoodpeckerCIInfo:
    """Parsed metadata about a Woodpecker CI pipeline file."""

    path: str
    steps: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class WoodpeckerCIStats:
    """Aggregate Woodpecker CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_woodpecker_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in WOODPECKER_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(WOODPECKER_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    if lower.endswith(".woodpecker.yml") or lower.endswith(".woodpecker.yaml"):
        return True
    return False


class WoodpeckerCIAnalyzer:
    """Audit Woodpecker CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.woodpecker.yml` for curl-pipe-to-shell, privileged containers, host networking,
    unpinned plugins, trusted mode, and secrets in environment blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WoodpeckerCIFinding] | None = None
        self._stats: WoodpeckerCIStats | None = None
        self._infos: list[WoodpeckerCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Woodpecker CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_woodpecker_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[WoodpeckerCIFinding], WoodpeckerCIInfo]:
        findings: list[WoodpeckerCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, WoodpeckerCIInfo(path=rel)

        info = WoodpeckerCIInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_plugin = ""
        in_plugin_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            name_match = re.match(r"^\s*-\s*name\s*:\s*[\"']?([^\"']+)", raw, re.IGNORECASE)
            if name_match:
                step_name = name_match.group(1).strip()
                if UNPINNED_PLUGIN_PATTERN.match(raw):
                    info.plugins.append(step_name)
                    current_plugin = step_name
                    in_plugin_block = True
                else:
                    info.steps.append(step_name)
                    in_security_step = bool(SECURITY_STEP_PATTERN.search(step_name))
                    in_plugin_block = False
                    current_plugin = ""

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    WoodpeckerCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Woodpecker secrets or encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="WOODPECKER_* variable interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_plugin_block and FLOATING_PLUGIN_TAG_PATTERN.match(line):
                findings.append(
                    WoodpeckerCIFinding(
                        kind="unpinned_plugin",
                        severity="medium",
                        message=f"plugin '{current_plugin}' uses floating tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if TRUSTED_PATTERN.match(line):
                findings.append(
                    WoodpeckerCIFinding(
                        kind="trusted_mode",
                        severity="high",
                        message="trusted: true allows privileged operations — restrict to protected branches",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
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
                    WoodpeckerCIFinding(
                        kind="root_user",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNSAFE_WHEN_PATTERN.search(line):
                findings.append(
                    WoodpeckerCIFinding(
                        kind="unsafe_when_condition",
                        severity="medium",
                        message="when condition uses untrusted WOODPECKER_* variable — validate inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(r"^\s*failure\s*:\s*ignore", line, re.IGNORECASE):
                findings.append(
                    WoodpeckerCIFinding(
                        kind="security_failure_ignored",
                        severity="medium",
                        message="security step ignores failures — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[WoodpeckerCIFinding]:
        """Scan Woodpecker CI pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[WoodpeckerCIFinding] = []
        infos: list[WoodpeckerCIInfo] = []
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
        self._stats = WoodpeckerCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> WoodpeckerCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[WoodpeckerCIInfo]:
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
        """Scaffold a hardened Woodpecker CI pipeline template."""
        return """\
# Generated by DevAI WoodpeckerCIAnalyzer
when:
  - event: push
    branch: main
  - event: pull_request

steps:
  - name: test
    image: python:3.12-slim
    commands:
      - pip install -e ".[dev]"
      - python -m pytest

  - name: security-scan
    image: python:3.12-slim
    commands:
      - pip install devai
      - devai security-scan .
    depends_on:
      - test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Woodpecker CI: none found"
        return (
            f"Woodpecker CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Woodpecker CI pipeline analysis:",
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
