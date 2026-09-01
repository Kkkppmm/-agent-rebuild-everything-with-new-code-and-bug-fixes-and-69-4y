"""ScikitBuildAnalyzer — audit scikit-build-core pyproject.toml and CMakeLists.txt for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SCIKIT_PYPROJECT_NAMES = ("pyproject.toml",)
CMAKE_LISTS_NAMES = ("CMakeLists.txt",)
SCIKIT_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.scikit-build\]|^\[tool\.scikit-build\.|"
    r"scikit-build-core|scikit_build_core)",
    re.IGNORECASE | re.MULTILINE,
)
CMAKE_MARKER_PATTERN = re.compile(
    r"(?:cmake_minimum_required|project\s*\(|add_subdirectory|FetchContent)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
CMAKE_EXEC_PROCESS_PATTERN = re.compile(
    r"execute_process\s*\([^)]*(?:curl|wget|bash|sh\s)",
    re.IGNORECASE,
)
CMAKE_DOWNLOAD_HTTP_PATTERN = re.compile(
    r"file\s*\(\s*DOWNLOAD\s+[\"']http://",
    re.IGNORECASE,
)
FETCH_CONTENT_HTTP_PATTERN = re.compile(
    r"FetchContent_Declare\s*\([^)]*GIT_REPOSITORY\s+[\"']?http://",
    re.IGNORECASE,
)
CMAKE_SYSTEM_COMMAND_PATTERN = re.compile(
    r"add_custom_command\s*\([^)]*COMMAND\s+[^)]*(?:;|\||&&)",
    re.IGNORECASE,
)
UNPINNED_FETCH_PATTERN = re.compile(
    r"GIT_TAG\s+[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)


@dataclass
class ScikitBuildFinding:
    """A security or best-practice issue in a scikit-build configuration file."""

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
class ScikitBuildInfo:
    """Parsed metadata about a scikit-build configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    cmake_targets: list[str] = field(default_factory=list)


@dataclass
class ScikitBuildStats:
    """Aggregate scikit-build analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_scikit_build_file(path: Path) -> bool:
    """Return True if the path looks like a scikit-build configuration file."""
    name = path.name
    if name in CMAKE_LISTS_NAMES:
        return True
    if name in SCIKIT_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if SCIKIT_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "CMakeLists.txt":
        return "cmake"
    return "unknown"


class ScikitBuildAnalyzer:
    """Audit scikit-build-core configuration for security issues.

    Scans pyproject.toml (with [tool.scikit-build]) and CMakeLists.txt for
    hardcoded secrets, insecure HTTP downloads, execute_process with shell
    commands, unpinned FetchContent git tags, and curl-pipe-to-shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ScikitBuildFinding] | None = None
        self._stats: ScikitBuildStats | None = None
        self._infos: list[ScikitBuildInfo] | None = None

    def configs(self) -> list[Path]:
        """Return scikit-build configuration paths found in the project."""
        found: list[Path] = []
        has_scikit_pyproject = False
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if path.name in SCIKIT_PYPROJECT_NAMES:
                try:
                    head = path.read_text(encoding="utf-8", errors="replace")[:8192]
                    if SCIKIT_MARKER_PATTERN.search(head):
                        has_scikit_pyproject = True
                        found.append(path)
                except OSError:
                    pass
            elif path.name in CMAKE_LISTS_NAMES:
                try:
                    head = path.read_text(encoding="utf-8", errors="replace")[:8192]
                    if CMAKE_MARKER_PATTERN.search(head):
                        found.append(path)
                except OSError:
                    pass
        if has_scikit_pyproject:
            for path in sorted(self.root.rglob("CMakeLists.txt")):
                if path.is_file() and path not in found:
                    found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ScikitBuildFinding], ScikitBuildInfo]:
        findings: list[ScikitBuildFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ScikitBuildInfo(path=rel)

        raw_lines = text.splitlines()
        info = ScikitBuildInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            target_match = re.search(
                r"(?:add_library|add_executable)\s*\(\s*([A-Za-z0-9_-]+)",
                stripped,
                re.IGNORECASE,
            )
            if target_match:
                info.cmake_targets.append(target_match.group(1))

            checks: list[tuple[str, str, str, re.Pattern[str]]] = [
                ("hardcoded_secret", "high", "hardcoded secret in scikit-build config — use env vars", HARDCODED_SECRET_PATTERN),
                ("pypi_token", "high", "PyPI token in scikit-build config — use CI secret stores", PYPI_TOKEN_PATTERN),
                ("scm_credentials", "high", "credentials embedded in repository URL — use SSH or token env vars", SCM_CREDENTIALS_PATTERN),
                ("curl_pipe_shell", "high", "curl/wget piped to shell — vendor scripts with checksum verification", CURL_PIPE_SHELL_PATTERN),
                ("sensitive_path", "high", "sensitive host path reference in build config", SENSITIVE_PATH_PATTERN),
                ("insecure_http", "medium", "insecure HTTP URL — use HTTPS for downloads and registries", INSECURE_HTTP_PATTERN),
                ("cmake_exec_process", "high", "execute_process with shell/download command — review for supply-chain risks", CMAKE_EXEC_PROCESS_PATTERN),
                ("cmake_download_http", "high", "file(DOWNLOAD) over HTTP — use HTTPS with checksum verification", CMAKE_DOWNLOAD_HTTP_PATTERN),
                ("fetch_content_http", "medium", "FetchContent from HTTP git URL — use HTTPS", FETCH_CONTENT_HTTP_PATTERN),
                ("unpinned_fetch", "medium", "FetchContent pinned to moving branch — pin to tag or commit SHA", UNPINNED_FETCH_PATTERN),
                ("cmake_shell_chain", "high", "chained shell commands in add_custom_command — avoid injection risks", CMAKE_SYSTEM_COMMAND_PATTERN),
            ]
            for kind, severity, message, pattern in checks:
                if pattern.search(line):
                    findings.append(
                        ScikitBuildFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        return findings, info

    def analyze(self) -> list[ScikitBuildFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ScikitBuildFinding] = []
        infos: list[ScikitBuildInfo] = []
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
        self._stats = ScikitBuildStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ScikitBuildStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ScikitBuildInfo]:
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
        """Scaffold a hardened [tool.scikit-build] snippet with secure defaults."""
        return """\
# pyproject.toml — hardened scikit-build-core defaults
[build-system]
requires = ["scikit-build-core>=0.5"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
# Pin CMake dependencies via FetchContent with GIT_TAG = commit SHA
# Use HTTPS URLs only; verify checksums for downloaded archives
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "scikit-build configs: none found"
        return (
            f"scikit-build configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "scikit-build analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            targets = ", ".join(info.cmake_targets[:8]) if info.cmake_targets else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): targets={targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
