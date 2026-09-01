"""ScikitBuildAnalyzer — audit scikit-build-core pyproject.toml and CMakeLists.txt for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SCIKIT_PYPROJECT_NAMES = ("pyproject.toml",)
SCIKIT_CMAKE_NAMES = ("CMakeLists.txt",)
SCIKIT_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.scikit-build\]|^\[tool\.scikit-build-core\]|scikit-build|"
    r"scikit_build_core|cmake\.args|wheel\.expand)",
    re.IGNORECASE | re.MULTILINE,
)
SCIKIT_CMAKE_MARKER_PATTERN = re.compile(
    r"(?:scikit-build|scikit_build|SKBUILD|pybind11_add_module|"
    r"Python3_add_library|nanobind_add_module)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:-D)?(?:CMAKE_TLS_VERIFY|SSL_VERIFY|VERIFY_SSL)\s*[=: ]\s*(?:OFF|FALSE|0|NO)\b|"
    r"ssl[_-]?verify\s*[=:]\s*(?:false|0|off)\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:GIT_TAG|GIT_BRANCH|GIT_REF|git|rev|branch|tag)\s*[=:]\s*"
    r"[\"']?(?:main|master|HEAD|develop)[\"']?|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
FETCH_CONTENT_PATTERN = re.compile(r"\bFetchContent_Declare\s*\(", re.IGNORECASE)
EXECUTE_PROCESS_PATTERN = re.compile(r"\bexecute_process\s*\(", re.IGNORECASE)
CMAKE_SECRET_PATTERN = re.compile(
    r"set\s*\(\s*[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY)[A-Z0-9_]*\s+"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
INSECURE_COMPILE_PATTERN = re.compile(
    r"-fno-stack-protector|-z\s+execstack|-D_FORTIFY_SOURCE=0",
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
    build_targets: list[str] = field(default_factory=list)


@dataclass
class ScikitBuildStats:
    """Aggregate scikit-build analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_scikit_build_file(path: Path, has_pyproject_scikit: bool) -> bool:
    """Return True if the path looks like a scikit-build configuration file."""
    name = path.name
    if name in SCIKIT_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if SCIKIT_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
        return False
    if name in SCIKIT_CMAKE_NAMES and has_pyproject_scikit:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if SCIKIT_CMAKE_MARKER_PATTERN.search(head):
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

    Scans pyproject.toml (with [tool.scikit-build] or [tool.scikit-build-core])
    and related CMakeLists.txt for hardcoded secrets in cmake.args, insecure
    HTTP URLs, credentials in git/source URLs, unpinned FetchContent dependencies,
    disabled TLS verification, dangerous execute_process calls, and insecure
    compile flags.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ScikitBuildFinding] | None = None
        self._stats: ScikitBuildStats | None = None
        self._infos: list[ScikitBuildInfo] | None = None

    def _has_scikit_pyproject(self) -> bool:
        for path in self.root.rglob("pyproject.toml"):
            if path.is_file():
                try:
                    head = path.read_text(encoding="utf-8", errors="replace")[:8192]
                    if SCIKIT_MARKER_PATTERN.search(head):
                        return True
                except OSError:
                    continue
        return False

    def configs(self) -> list[Path]:
        """Return scikit-build configuration paths found in the project."""
        has_scikit = self._has_scikit_pyproject()
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_scikit_build_file(path, has_scikit):
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
                r"cmake\.args\s*=\s*\[([^\]]+)\]", stripped, re.IGNORECASE
            )
            if cmake_arg_match:
                info.cmake_args.extend(
                    a.strip().strip("\"'")
                    for a in cmake_arg_match.group(1).split(",")
                    if a.strip()
                )

            target_match = re.search(
                r"(?:build\.targets|wheel\.packages)\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if target_match:
                info.build_targets.extend(
                    t.strip().strip("\"'")
                    for t in target_match.group(1).split(",")
                    if t.strip()
                )

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
                        message="PyPI token in scikit-build config — use env vars or CI secrets",
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
                        message="AWS access key in scikit-build config — use credential helpers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CMAKE_SECRET_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="cmake_secret",
                        severity="high",
                        message="hardcoded secret in CMake — use environment variables or CMake cache from CI",
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
                        message="insecure HTTP URL — use HTTPS for downloads and package indexes",
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

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in build config — vendor scripts with checksum verification",
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
                        message="TLS verification disabled — keep CMAKE_TLS_VERIFY enabled",
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
                        message="sensitive host path reference — avoid bundling credentials in extension builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FETCH_CONTENT_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="fetch_content",
                        severity="medium",
                        message="FetchContent without pinned hash — pin external dependencies to commit SHAs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EXECUTE_PROCESS_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="execute_process",
                        severity="medium",
                        message="execute_process in CMake — review for command injection and network fetches",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_COMPILE_PATTERN.search(line):
                findings.append(
                    ScikitBuildFinding(
                        kind="insecure_compile",
                        severity="medium",
                        message="insecure compile flags — avoid disabling stack protection or fortify source",
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
        """Scaffold a hardened scikit-build-core pyproject.toml snippet."""
        return """\
# pyproject.toml — hardened scikit-build-core defaults
[build-system]
requires = ["scikit-build-core>=0.9", "pybind11"]
build-backend = "scikit_build_core.build"

[tool.scikit-build]
# Pin cmake.args; never embed secrets in pyproject.toml
cmake.args = ["-DCMAKE_BUILD_TYPE=Release"]
# Pin FetchContent dependencies to commit SHAs in CMakeLists.txt
# Store PyPI tokens via env vars in CI, not in config files
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
            args = ", ".join(info.cmake_args[:8]) if info.cmake_args else "none"
            targets = ", ".join(info.build_targets[:8]) if info.build_targets else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): cmake.args={args}, targets={targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
