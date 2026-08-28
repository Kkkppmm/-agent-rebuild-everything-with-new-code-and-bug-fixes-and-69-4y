"""BuildkiteAnalyzer — audit Buildkite pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUILDKITE_DIRS = (".buildkite", "buildkite", "ci")
BUILDKITE_NAMES = ("pipeline.yml", "pipeline.yaml")

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
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|--privileged\b)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:command|run)\s*:\s*.*\$\{?\s*BUILDKITE_",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*([a-z0-9_.-]+/[a-z0-9_.-]+)#(?:master|main|latest)\s*$",
    re.IGNORECASE,
)
FLOATING_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*([a-z0-9_.-]+/[a-z0-9_.-]+)#\d+\s*$",
    re.IGNORECASE,
)
PROPAGATE_ENV_PATTERN = re.compile(
    r"^\s*propagate_environment\s*:\s*true\s*$",
    re.IGNORECASE,
)
SENSITIVE_ARTIFACT_PATTERN = re.compile(
    r"artifact_paths\s*:\s*.*\.env",
    re.IGNORECASE,
)
AGENT_HOOK_PATTERN = re.compile(
    r"^\s*(?:pre-command|post-command|pre-checkout|post-checkout)\s*:\s*",
    re.IGNORECASE,
)
SECURITY_JOB_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)


@dataclass
class BuildkiteFinding:
    """A security or best-practice issue in a Buildkite pipeline."""

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
class BuildkiteInfo:
    """Parsed metadata about a Buildkite pipeline file."""

    path: str
    steps: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class BuildkiteStats:
    """Aggregate Buildkite analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_buildkite_file(path: Path) -> bool:
    lower = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if ".buildkite" in parts and lower in BUILDKITE_NAMES:
        return True
    if parts & set(BUILDKITE_DIRS) and lower in BUILDKITE_NAMES:
        return True
    if lower.endswith(".buildkite.yml") or lower.endswith(".buildkite.yaml"):
        return True
    return False


class BuildkiteAnalyzer:
    """Audit Buildkite pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.buildkite/pipeline.yml` for curl-pipe-to-shell, unpinned plugins, privileged
    Docker, environment propagation, and secrets in command blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BuildkiteFinding] | None = None
        self._stats: BuildkiteStats | None = None
        self._infos: list[BuildkiteInfo] | None = None

    def files(self) -> list[Path]:
        """Return Buildkite pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_buildkite_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BuildkiteFinding], BuildkiteInfo]:
        findings: list[BuildkiteFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BuildkiteInfo(path=rel)

        info = BuildkiteInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_step = ""
        in_artifact_paths = False
        artifact_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*artifact_paths\s*:", raw, re.IGNORECASE):
                in_artifact_paths = True
                artifact_indent = len(raw) - len(raw.lstrip())
                if SENSITIVE_ARTIFACT_PATTERN.search(line):
                    findings.append(
                        BuildkiteFinding(
                            kind="sensitive_artifact",
                            severity="high",
                            message="artifact_paths includes .env — may leak secrets in build artifacts",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if in_artifact_paths:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= artifact_indent and not line.startswith("-"):
                    in_artifact_paths = False
                elif re.search(r"\.env\b", line):
                    findings.append(
                        BuildkiteFinding(
                            kind="sensitive_artifact",
                            severity="high",
                            message="artifact_paths includes .env — may leak secrets in build artifacts",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            label_match = re.match(r"^\s*-\s*label\s*:\s*[\"']?([^\"']+)", raw, re.IGNORECASE)
            if label_match:
                current_step = label_match.group(1).strip()
                info.steps.append(current_step)
                in_security_step = bool(SECURITY_JOB_PATTERN.search(current_step))

            agents_match = re.match(r"^\s*agents\s*:\s*(.+)$", raw, re.IGNORECASE)
            if agents_match:
                info.agents.append(agents_match.group(1).strip())

            plugin_match = re.match(r"^\s*-\s*([a-z0-9_.-]+/[a-z0-9_.-]+)#", raw, re.IGNORECASE)
            if plugin_match:
                info.plugins.append(plugin_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Buildkite secrets or environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and use checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
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
                    BuildkiteFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_PLUGIN_PATTERN.match(line):
                findings.append(
                    BuildkiteFinding(
                        kind="unpinned_plugin",
                        severity="medium",
                        message="plugin uses floating tag (master/main/latest) — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_PLUGIN_PATTERN.match(line):
                findings.append(
                    BuildkiteFinding(
                        kind="floating_plugin_version",
                        severity="low",
                        message="plugin uses major-only version — pin to full semver for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="script_injection",
                        severity="high",
                        message="unquoted BUILDKITE_* variable in command — validate untrusted input",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PROPAGATE_ENV_PATTERN.match(line):
                findings.append(
                    BuildkiteFinding(
                        kind="propagate_environment",
                        severity="medium",
                        message="propagate_environment leaks parent env to child steps — restrict sensitive vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AGENT_HOOK_PATTERN.match(line) and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="unsafe_agent_hook",
                        severity="high",
                        message="agent hook runs curl-pipe-to-shell — hooks execute with agent privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    BuildkiteFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(r"^\s*soft_fail\s*:\s*true", line, re.IGNORECASE):
                findings.append(
                    BuildkiteFinding(
                        kind="security_soft_fail",
                        severity="medium",
                        message="security step configured with soft_fail — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[BuildkiteFinding]:
        """Scan Buildkite pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BuildkiteFinding] = []
        infos: list[BuildkiteInfo] = []
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
        self._stats = BuildkiteStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BuildkiteStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BuildkiteInfo]:
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
        """Scaffold a hardened Buildkite pipeline template."""
        return """\
# Generated by DevAI BuildkiteAnalyzer
steps:
  - label: ":pytest: Tests"
    command: python -m pytest
    agents:
      queue: default

  - label: ":shield: Security scan"
    command: |
      pip install devai
      devai security-scan .
    agents:
      queue: default
    depends_on: ~
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Buildkite: none found"
        return (
            f"Buildkite: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Buildkite pipeline analysis:",
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
