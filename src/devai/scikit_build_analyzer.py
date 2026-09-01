"""ScikitBuildAnalyzer — audit scikit-build-core pyproject.toml and CMakeLists.txt for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKBUILD_PYPROJECT_NAMES = ("pyproject.toml",)
SKBUILD_CMAKE_NAMES = ("CMakeLists.txt",)
SKBUILD_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.scikit-build\]|^\[tool\.scikit-build\.|scikit-build-core|"
    r"scikit_build_core)",
    re.IGNORECASE | re.MULTILINE,
)
CMAKE_MARKER_PATTERN = re.compile(
    r"(?:FetchContent|ExternalProject|find_package|add_subdirectory)",
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
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:GIT_TAG|GIT_BRANCH|GIT_SHALLOW)\s+(?:main|master|HEAD|develop)\b|"
    r"GIT_REPOSITORY\s+.*@(?:main|master|HEAD|develop)",
    re.IGNORECASE,
)
FETCHCONTENT_HTTP_PATTERN = re.compile(
    r"FetchContent_Declare\s*\([^)]*http://",
    re.IGNORECASE | re.DOTALL,
)
INSECURE_CMAKE_FLAG_PATTERN = re.compile(
    r"(?:CMAKE_TLS_VERIFY\s+OFF|CMAKE_SSL_NO_VERIFY|"
    r"-DCMAKE_TLS_VERIFY:BOOL=OFF)",
    re.IGNORECASE,
)
DANGEROUS_CMAKE_CMD_PATTERN = re.compile(
    r"(?:execute_process|add_custom_command)\s*\([^)]*(?:curl|wget|bash|sh\s)",
    re.IGNORECASE | re.DOTALL,
)
UNPINNED_FETCHCONTENT_PATTERN = re.compile(
    r"FetchContent_Declare\s*\([^)]*\)(?![\s\S]*GIT_TAG)",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"[a-zA-Z0-9_.-]+\s*=\s*[\"']\*[\"']",
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
    cmake_args: list[str] = field(default_factory=list)
    fetch_deps: list[str] = field(default_factory=list)


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
    if name in SKBUILD_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if SKBUILD_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    if name in SKBUILD_CMAKE_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CMAKE_MARKER_PATTERN.search(head):
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

    Scans pyproject.toml [tool.scikit-build] and CMakeLists.txt for hardcoded
    secrets, insecure HTTP FetchContent URLs, disabled TLS verification,
    unpinned git dependencies, and dangerous execute_process commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ScikitBuildFinding] | None = None
        self._stats: ScikitBuildStats | None = None
        self._infos: list[ScikitBuildInfo] | None = None

    def configs(self) -> list[Path]:
        """Return scikit-build configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_scikit_build_file(path):
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

            cmake_arg_match = re.search(
                r"cmake\.args\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if cmake_arg_match:
                info.cmake_args.extend(a.strip().strip("\"'") for a in cmake_arg_match.group(1).split(","))

            fetch_match = re.search(
                r"FetchContent_Declare\s*\(\s*(\w+)",
                stripped,
                re.IGNORECASE,
            )
            if fetch_match:
                info.fetch_deps.append(fetch_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in scikit-build config — use CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in scikit-build config — use env vars for publishing",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_http",
                        severity="high",
                        message="insecure HTTP URL in scikit-build/CMake config — use HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in git/source URL — use SSH keys or token env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="unpinned git dependency in CMake — pin GIT_TAG to a commit or tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_CMAKE_FLAG_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_cmake_flag",
                        severity="high",
                        message="disabled TLS verification in CMake flags",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_CMAKE_CMD_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="dangerous_cmake_command",
                        severity="high",
                        message="dangerous execute_process/add_custom_command in CMake — review for injection",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="unpinned or wildcard version constraint — pin dependencies",
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
        """Scaffold a hardened scikit-build config snippet with secure defaults."""
        return """\
# pyproject.toml — hardened scikit-build-core defaults
[build-system]
requires = ["scikit-build-core>=0.5"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
cmake.version = ">=3.15"
# Pin FetchContent GIT_TAG in CMakeLists.txt; use HTTPS only
# Store publish credentials via env vars, never in pyproject.toml
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Scikit-build configs: none found"
        return (
            f"Scikit-build configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Scikit-build analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            args = ", ".join(info.cmake_args[:6]) if info.cmake_args else "none"
            deps = ", ".join(info.fetch_deps[:6]) if info.fetch_deps else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.cmake_args)} cmake arg(s), {len(info.fetch_deps)} FetchContent dep(s)"
            )
            lines.append(f"    cmake args: {args}")
            lines.append(f"    fetch deps: {deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
