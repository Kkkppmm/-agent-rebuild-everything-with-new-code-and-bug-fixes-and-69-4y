"""ScikitBuildAnalyzer — audit scikit-build-core pyproject.toml and CMakeLists.txt configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SCIKIT_PYPROJECT_NAMES = ("pyproject.toml",)
SCIKIT_CMAKE_NAMES = ("CMakeLists.txt",)
SCIKIT_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.scikit-build\]|^\[tool\.scikit-build\.|scikit[_-]?build[_-]?core|"
    r"build-backend\s*=\s*[\"']scikit_build_core|requires\s*=\s*\[[^\]]*scikit[_-]?build)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|http-basic)\s*[=:]\s*"
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
    r"version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:GIT_REPOSITORY|GIT_TAG|GIT_BRANCH|GIT_SHALLOW)\s+[^\n]*|"
    r"(?:branch|rev|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"git@github\.com:[^\s]+#(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|CMAKE_TLS_VERIFY\s*=\s*OFF|"
    r"CMAKE_TLS_VERIFY\s+OFF|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.env\b)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:cmake\.source-dir|cmake\.build-dir|wheel\.packages|sdist\.include|"
    r"CMAKE_SOURCE_DIR|CMAKE_BINARY_DIR)\s*[= ]*[\"']?\.\./|"
    r"add_subdirectory\s*\(\s*\.\./",
    re.IGNORECASE,
)
SENSITIVE_INCLUDE_PATTERN = re.compile(
    r"(?:include|exclude|wheel\.packages|sdist\.include)\s*=\s*\[[^\]]*(?:\.env|\.ssh|\.aws|secrets?)",
    re.IGNORECASE,
)
CMAKE_EXECUTE_PROCESS_PATTERN = re.compile(
    r"execute_process\s*\(",
    re.IGNORECASE,
)
FETCHCONTENT_PATTERN = re.compile(
    r"FetchContent_Declare\s*\(",
    re.IGNORECASE,
)
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh|"
    r"eval\s+\$|sudo\s+)",
    re.IGNORECASE,
)
INSECURE_CMAKE_FLAG_PATTERN = re.compile(
    r"(?:CMAKE_DISABLE_FIND_PACKAGE|CMAKE_SKIP_INSTALL_ALL_DEPENDENCY|"
    r"FETCHCONTENT_FULLY_DISCONNECTED\s*=\s*OFF|"
    r"CMAKE_FIND_USE_PACKAGE_REGISTRY\s*=\s*ON)",
    re.IGNORECASE,
)
BUILD_HOOK_PATTERN = re.compile(
    r"(?:metadata\.version\.provider|build\.targets|"
    r"before-build|after-build)\s*=",
    re.IGNORECASE,
)


@dataclass
class ScikitBuildFinding:
    """A security or best-practice issue in a scikit-build-core configuration file."""

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
    """Parsed metadata about a scikit-build-core configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    cmake_version: str = ""
    packages: list[str] = field(default_factory=list)
    build_targets: list[str] = field(default_factory=list)


@dataclass
class ScikitBuildStats:
    """Aggregate scikit-build-core analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _has_scikit_build_marker(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(SCIKIT_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _scikit_build_roots(root: Path) -> set[Path]:
    """Return directories that contain scikit-build-core configuration."""
    roots: set[Path] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in SCIKIT_PYPROJECT_NAMES and _has_scikit_build_marker(path):
            roots.add(path.parent)
    return roots


def _is_scikit_build_file(path: Path, scikit_roots: set[Path]) -> bool:
    """Return True if the path looks like a scikit-build-core configuration file."""
    name = path.name
    if name in SCIKIT_PYPROJECT_NAMES and _has_scikit_build_marker(path):
        return True
    if name in SCIKIT_CMAKE_NAMES:
        for project_root in scikit_roots:
            try:
                path.relative_to(project_root)
                return True
            except ValueError:
                continue
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

    Scans pyproject.toml (with [tool.scikit-build]) and associated CMakeLists.txt
    for hardcoded PyPI tokens, insecure HTTP URLs, credentials in git/source URLs,
    unpinned FetchContent/git dependencies, path traversal in cmake source dirs,
    sensitive files in wheel/sdist includes, curl-pipe-to-shell in execute_process,
    disabled TLS verification, and dangerous CMake build hooks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ScikitBuildFinding] | None = None
        self._stats: ScikitBuildStats | None = None
        self._infos: list[ScikitBuildInfo] | None = None

    def configs(self) -> list[Path]:
        """Return scikit-build-core configuration paths found in the project."""
        scikit_roots = _scikit_build_roots(self.root)
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_scikit_build_file(path, scikit_roots):
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
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            cmake_ver_match = re.search(
                r"cmake\.version\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if cmake_ver_match:
                info.cmake_version = cmake_ver_match.group(1)

            packages_match = re.search(
                r"wheel\.packages\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if packages_match:
                for pkg in re.findall(r"[\"']([^\"']+)[\"']", packages_match.group(1)):
                    if pkg not in info.packages:
                        info.packages.append(pkg)

            target_match = re.search(
                r"build\.targets\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if target_match:
                for target in re.findall(r"[\"']([^\"']+)[\"']", target_match.group(1)):
                    if target not in info.build_targets:
                        info.build_targets.append(target)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in scikit-build config — use CI secret stores or env vars",
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
                        message="PyPI token in scikit-build config — use TWINE_PASSWORD or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in scikit-build config — use OIDC or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and dependency downloads",
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
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                and (
                    re.search(
                        r"(?:dependencies|requires|build-system)",
                        stripped,
                        re.IGNORECASE,
                    )
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    ScikitBuildFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies for reproducible builds",
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
                        message="git/FetchContent dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in scikit-build config — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_COMMAND_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="dangerous_command",
                        severity="high",
                        message="dangerous command in scikit-build/CMake config — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in wheels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PATH_TRAVERSAL_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="path_traversal",
                        severity="high",
                        message="path traversal in cmake source-dir or add_subdirectory — keep paths within project root",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_INCLUDE_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="sensitive_include",
                        severity="high",
                        message="sensitive file pattern in wheel/sdist include — avoid shipping secrets in wheels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CMAKE_EXECUTE_PROCESS_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="cmake_execute_process",
                        severity="medium",
                        message="execute_process in CMakeLists.txt — review for supply-chain and arbitrary code execution risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FETCHCONTENT_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="fetchcontent",
                        severity="medium",
                        message="FetchContent in CMakeLists.txt — pin external dependencies to immutable tags or SHAs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BUILD_HOOK_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="build_hook",
                        severity="medium",
                        message="custom build hook in scikit-build config — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_CMAKE_FLAG_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_cmake_flag",
                        severity="medium",
                        message="insecure CMake flag — avoid disabling package registry or TLS checks",
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
        """Scaffold a hardened pyproject.toml [tool.scikit-build] snippet with secure defaults."""
        return """\
# pyproject.toml — hardened [tool.scikit-build] defaults for C/C++/CMake extensions
[build-system]
requires = ["scikit-build-core>=0.9,<1.0"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
cmake.version = ">=3.15"
cmake.build-type = "Release"
wheel.packages = ["my_package"]
# Pin FetchContent dependencies to tags or commit SHAs in CMakeLists.txt
# Store publish tokens via CI secrets:
#   export TWINE_PASSWORD=pypi-<token>
# Never commit tokens in pyproject.toml or CMakeLists.txt
# Keep cmake.source-dir and add_subdirectory paths within project root
# Avoid execute_process with network downloads; vendor dependencies with checksums
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
            packages = ", ".join(info.packages[:8]) if info.packages else "none"
            targets = ", ".join(info.build_targets[:8]) if info.build_targets else "none"
            cmake_ver = info.cmake_version or "unspecified"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"cmake {cmake_ver}, {len(info.packages)} package(s)"
            )
            lines.append(f"    packages: {packages}")
            lines.append(f"    build targets: {targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
