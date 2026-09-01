"""PixiAnalyzer — audit Pixi pixi.toml and pixi.lock for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIXI_CONFIG_NAMES = ("pixi.toml",)
PIXI_LOCK_NAMES = ("pixi.lock",)
PIXI_MARKER_PATTERN = re.compile(
    r"(?:^\[workspace\]|^\[pypi-dependencies\]|^\[pypi_dependencies\]|"
    r"^\[environments\]|^\[feature\]|^\[tasks\]|channels\s*=\s*\[|platforms\s*=\s*\[)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|conda[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"=\s*[\"'][^\"']*>=[^\"']*[\"']|"
    r"=\s*[\"'][^\"']*<=[^\"']*[\"']|"
    r"=\s*[\"'][^\"']*>[^\"']*[\"']|"
    r"=\s*[\"'][^\"']*<[^\"']*[\"']",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:@main\b|@master\b|@HEAD\b|@develop\b|branch\s*=\s*[\"'](?:main|master|HEAD|develop)[\"'])",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:ssl_verify\s*=\s*false|verify_ssl\s*=\s*false|"
    r"insecure\s*=\s*true|ssl-no-revoke|trusted-host\s*=)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
CHANNEL_PATTERN = re.compile(
    r"channels\s*=\s*\[([^\]]+)\]",
    re.IGNORECASE,
)
DEPENDENCY_PATTERN = re.compile(
    r"^([a-zA-Z0-9_.-]+)\s*=\s*",
)
TASK_SCRIPT_PATTERN = re.compile(
    r"^([a-zA-Z0-9_.-]+)\s*=\s*[\"'](.+)[\"']",
)


@dataclass
class PixiFinding:
    """A security or best-practice issue in a Pixi configuration file."""

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
class PixiInfo:
    """Parsed metadata about a Pixi configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)


@dataclass
class PixiStats:
    """Aggregate Pixi analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pixi_config(path: Path) -> bool:
    """Return True if the path looks like a Pixi configuration file."""
    name = path.name.lower()
    if name in PIXI_CONFIG_NAMES:
        return True
    if name == "pyproject.toml":
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if PIXI_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name in PIXI_CONFIG_NAMES:
        return "pixi"
    if name == "pyproject.toml":
        return "pyproject"
    return "unknown"


class PixiAnalyzer:
    """Audit Pixi pixi.toml and lockfiles for security issues.

    Scans pixi.toml for hardcoded tokens, insecure HTTP channels, credentials
    in git URLs, unpinned dependencies, loose version constraints, disabled SSL
    verification, missing lockfiles, and curl-pipe-to-shell in task scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PixiFinding] | None = None
        self._stats: PixiStats | None = None
        self._infos: list[PixiInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Pixi configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pixi_config(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PixiFinding], PixiInfo]:
        findings: list[PixiFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PixiInfo(path=rel)

        raw_lines = text.splitlines()
        info = PixiInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_dependencies = False
        in_pypi_deps = False
        in_tasks = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            lower = stripped.lower()
            if lower in ("[dependencies]", "[pypi-dependencies]", "[pypi_dependencies]"):
                in_dependencies = lower == "[dependencies]"
                in_pypi_deps = lower in ("[pypi-dependencies]", "[pypi_dependencies]")
                in_tasks = False
                continue
            if lower == "[tasks]":
                in_tasks = True
                in_dependencies = False
                in_pypi_deps = False
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_dependencies = False
                in_pypi_deps = False
                in_tasks = False

            channel_match = CHANNEL_PATTERN.search(stripped)
            if channel_match:
                for ch in re.findall(r"[\"']([^\"']+)[\"']", channel_match.group(1)):
                    info.channels.append(ch)

            if (in_dependencies or in_pypi_deps) and "=" in stripped:
                dep_match = DEPENDENCY_PATTERN.match(stripped)
                if dep_match:
                    prefix = "pypi:" if in_pypi_deps else ""
                    info.dependencies.append(f"{prefix}{dep_match.group(1)}")

            if in_tasks:
                task_match = TASK_SCRIPT_PATTERN.match(stripped)
                if task_match:
                    info.tasks.append(task_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Pixi config — use environment variables or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in config — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Pixi config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for Pixi channels and direct URL deps",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in VCS URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(stripped) and (in_dependencies or in_pypi_deps):
                findings.append(
                    PixiFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies and commit pixi.lock",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep ssl_verify enabled for remote channels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PixiFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if path.name.lower() in PIXI_CONFIG_NAMES:
            parent = path.parent
            has_lock = any((parent / lock_name).exists() for lock_name in PIXI_LOCK_NAMES)
            if not has_lock:
                findings.append(
                    PixiFinding(
                        kind="missing_lockfile",
                        severity="low",
                        message="pixi.lock missing — commit lockfile for reproducible environments",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[PixiFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PixiFinding] = []
        infos: list[PixiInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = PixiStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PixiStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PixiInfo]:
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

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened pixi.toml snippet with secure defaults."""
        return """\
# pixi.toml — hardened defaults for Pixi projects
[workspace]
name = "myproject"
channels = ["conda-forge"]
platforms = ["linux-64", "osx-arm64", "win-64"]

[dependencies]
python = "3.12"
# Pin versions explicitly, e.g. numpy = "1.26.4"

[pypi-dependencies]
# requests = "==2.31.0"

[tasks]
test = "pytest"

# Generate and commit a lockfile for reproducible installs:
#   pixi install  (creates pixi.lock)
# Store credentials via environment variables — never commit tokens in pixi.toml
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pixi configs: none found"
        return (
            f"Pixi configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pixi analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            channels = ", ".join(info.channels[:8]) if info.channels else "none"
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.channels)} channel(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    channels: {channels}")
            lines.append(f"    tasks: {tasks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
