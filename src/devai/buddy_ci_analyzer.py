"""BuddyCIAnalyzer — audit Buddy CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUDDY_FILENAMES = ("buddy.yml", "buddy.yaml")
BUDDY_DIRS = (".buddy", "buddy", "ci/buddy")
BUDDY_SUFFIXES = (".buddy.yml", ".buddy.yaml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:docker_image_tag|image_tag|tag)\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"^\s*docker_privileged_mode\s*:\s*true\s*$",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*docker_network_mode\s*:\s*[\"']?host[\"']?\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$BUDDY_(?:EXECUTION_PULL_REQUEST|EXECUTION_BRANCH|REPO_SLUG|PIPELINE_NAME|COMMIT_MESSAGE)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
FLOATING_IMAGE_TAG_PATTERN = re.compile(
    r"^\s*docker_image_tag\s*:\s*[\"']?(?:master|main|develop)[\"']?\s*$",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"/(?:etc/passwd|etc/shadow|root|home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
PIPELINE_NAME_PATTERN = re.compile(
    r"^\s*pipeline\s*:\s*[\"']?([^\"'\n]+)",
    re.IGNORECASE,
)
ACTION_NAME_PATTERN = re.compile(
    r"^\s*action\s*:\s*[\"']?([^\"'\n]+)",
    re.IGNORECASE,
)


@dataclass
class BuddyCIFinding:
    """A security or best-practice issue in a Buddy CI pipeline."""

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
class BuddyCIInfo:
    """Parsed metadata about a Buddy CI pipeline file."""

    path: str
    pipelines: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class BuddyCIStats:
    """Aggregate Buddy CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_buddy_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in BUDDY_FILENAMES:
        return True
    if any(lower.endswith(suffix) for suffix in BUDDY_SUFFIXES):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(BUDDY_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class BuddyCIAnalyzer:
    """Audit Buddy CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.buddy/` YAML files for curl-pipe-to-shell, privileged Docker mode,
    host networking, unpinned image tags, and Buddy variable injection in scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BuddyCIFinding] | None = None
        self._stats: BuddyCIStats | None = None
        self._infos: list[BuddyCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Buddy CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_buddy_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BuddyCIFinding], BuddyCIInfo]:
        findings: list[BuddyCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BuddyCIInfo(path=rel)

        info = BuddyCIInfo(path=rel, lines=len(raw_lines))
        in_security_action = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            pipeline_match = PIPELINE_NAME_PATTERN.match(raw)
            if pipeline_match:
                pipeline_name = pipeline_match.group(1).strip()
                info.pipelines.append(pipeline_name)

            action_match = ACTION_NAME_PATTERN.match(raw)
            if action_match:
                action_name = action_match.group(1).strip()
                info.actions.append(action_name)
                in_security_action = bool(SECURITY_STEP_PATTERN.search(action_name))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Buddy encrypted variables or vault",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_VALUE_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="hardcoded_secret_value",
                        severity="high",
                        message="hardcoded secret value pattern — use Buddy vault references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
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
                    BuddyCIFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_IMAGE_TAG_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="floating_image_tag",
                        severity="medium",
                        message="Docker image uses a floating branch tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount exposes host — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="docker_privileged_mode: true — run containers without elevated privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode — containers share host network namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="script_injection",
                        severity="high",
                        message="Buddy variable in script — sanitize PR/branch inputs to prevent injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    BuddyCIFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path mounted into container",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and not in_security_action:
                findings.append(
                    BuddyCIFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP URL — use HTTPS for external endpoints",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[BuddyCIFinding]:
        """Scan Buddy CI pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BuddyCIFinding] = []
        infos: list[BuddyCIInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = BuddyCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BuddyCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BuddyCIInfo]:
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
        """Scaffold a hardened Buddy CI pipeline template."""
        return """\
# Generated by DevAI BuddyCIAnalyzer
- pipeline: "main-pipeline"
  on: "PUSH"
  refs:
    - "refs/heads/main"
  fail_on_prepare_env_warning: true
  actions:
    - action: "Test"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "3.12-slim"
      execute_commands:
        - "pip install -e '.[dev]'"
        - "python -m pytest"

    - action: "Security Scan"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "3.12-slim"
      execute_commands:
        - "pip install devai"
        - "devai security-scan ."
      trigger_condition: "ALWAYS"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Buddy CI: none found"
        return (
            f"Buddy CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Buddy CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            actions = ", ".join(info.actions[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.pipelines)} pipeline(s), actions=[{actions}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
