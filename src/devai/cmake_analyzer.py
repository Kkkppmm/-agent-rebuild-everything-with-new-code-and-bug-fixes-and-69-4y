"""CMakeAnalyzer — audit CMakeLists.txt and cmake modules for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CMAKE_MANIFEST_NAMES = ("CMakeLists.txt",)
CMAKE_MODULE_SUFFIX = ".cmake"
CMAKE_MODULE_DIRS = ("cmake", "cmake/modules", "toolchains")
CMAKE_PRESET_NAMES = ("CMakePresets.json", "CMakeUserPresets.json")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:GIT_TAG|GIT_BRANCH|GIT_REF)\s+[\"']?(?:main|master|HEAD|develop)[\"']?|"
    r"\.git#(?:main|master|HEAD|develop)\b",
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
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:CMAKE_TLS_VERIFY|SSL_VERIFY|VERIFY_SSL)\s+(?:OFF|FALSE|0|NO)\b|"
    r"ssl[_-]?verify\s*[=:]\s*(?:false|0|off)\b",
    re.IGNORECASE,
)
INSECURE_COMPILE_PATTERN = re.compile(
    r"-fno-stack-protector|-z\s+execstack|-D_FORTIFY_SOURCE=0",
    re.IGNORECASE,
)
FETCH_WITHOUT_HASH_PATTERN = re.compile(
    r"\bfile\s*\(\s*DOWNLOAD\b",
    re.IGNORECASE,
)
EXTERNAL_PROJECT_PATTERN = re.compile(
    r"\bExternalProject_Add\s*\(",
    re.IGNORECASE,
)
FETCH_CONTENT_PATTERN = re.compile(
    r"\bFetchContent_Declare\s*\(",
    re.IGNORECASE,
)
EXECUTE_PROCESS_PATTERN = re.compile(
    r"\bexecute_process\s*\(",
    re.IGNORECASE,
)
FIND_PACKAGE_PATTERN = re.compile(
    r"\bfind_package\s*\(\s*([A-Za-z0-9_+-]+)",
    re.IGNORECASE,
)
CMAKE_SET_SECRET_PATTERN = re.compile(
    r"set\s*\(\s*[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)[A-Z0-9_]*\s+"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class CMakeFinding:
    """A security or best-practice issue in a CMake configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CMakeInfo:
    """Parsed metadata from a CMake configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "manifest"
    packages: list[str] = field(default_factory=list)
    external_projects: list[str] = field(default_factory=list)


@dataclass
class CMakeStats:
    """Aggregate statistics from CMake analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cmake_file(path: Path) -> bool:
    if path.name in CMAKE_MANIFEST_NAMES or path.name in CMAKE_PRESET_NAMES:
        return True
    if path.suffix == CMAKE_MODULE_SUFFIX:
        if any(part in CMAKE_MODULE_DIRS for part in path.parts):
            return True
        if path.parent.name in ("cmake", "toolchains"):
            return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "CMakeLists.txt":
        return "manifest"
    if name in CMAKE_PRESET_NAMES:
        return "presets"
    if path.suffix == CMAKE_MODULE_SUFFIX:
        return "module"
    return "unknown"


class CMakeAnalyzer:
    """Audit CMake configuration for security issues.

    Scans CMakeLists.txt, cmake/*.cmake, toolchain files, and CMakePresets.json
    for hardcoded secrets, insecure HTTP URLs, credentials in git URLs, unpinned
    git dependencies, dangerous execute_process calls, disabled TLS verification,
    insecure compile flags, and downloads without checksum verification.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CMakeFinding] | None = None
        self._stats: CMakeStats | None = None
        self._infos: list[CMakeInfo] | None = None

    def configs(self) -> list[Path]:
        """Return CMake configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cmake_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CMakeFinding],
        info: CMakeInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        pkg_match = FIND_PACKAGE_PATTERN.search(stripped)
        if pkg_match:
            info.packages.append(pkg_match.group(1))

        if EXTERNAL_PROJECT_PATTERN.search(stripped):
            info.external_projects.append(f"line {lineno}")

        if FETCH_CONTENT_PATTERN.search(stripped):
            info.external_projects.append(f"FetchContent line {lineno}")

        if HARDCODED_SECRET_PATTERN.search(line) or CMAKE_SET_SECRET_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in CMake config — use environment variables or CMake cache secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in CMake config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and repository URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency pinned to moving ref — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="tls_verify_off",
                    severity="high",
                    message="TLS verification disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in CMake — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and EXECUTE_PROCESS_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="dangerous_execute_process",
                    severity="high",
                    message="dangerous command in execute_process — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_COMPILE_PATTERN.search(line):
            findings.append(
                CMakeFinding(
                    kind="insecure_compile_flag",
                    severity="medium",
                    message="insecure compile flag — avoid disabling stack protection or fortify",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _check_download_hashes(
        self,
        raw_lines: list[str],
        rel: str,
        findings: list[CMakeFinding],
    ) -> None:
        for lineno, line in enumerate(raw_lines, start=1):
            if not FETCH_WITHOUT_HASH_PATTERN.search(line):
                continue
            window = "\n".join(raw_lines[lineno - 1 : lineno + 5]).upper()
            if "EXPECTED_HASH" not in window:
                findings.append(
                    CMakeFinding(
                        kind="download_without_hash",
                        severity="medium",
                        message="file(DOWNLOAD) without EXPECTED_HASH — verify download integrity",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[CMakeFinding], CMakeInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[CMakeFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CMakeInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = CMakeInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        self._check_download_hashes(raw_lines, rel, findings)

        return findings, info

    def analyze(self) -> list[CMakeFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CMakeFinding] = []
        infos: list[CMakeInfo] = []
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
        self._stats = CMakeStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CMakeStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CMakeInfo]:
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
        """Scaffold a hardened CMake toolchain snippet with secure defaults."""
        return """\
# cmake/SecurityDefaults.cmake — hardened defaults for CMake projects
# Store secrets via environment variables or CMake cache entries:
#   cmake -DAPI_TOKEN=$API_TOKEN ..
set(CMAKE_TLS_VERIFY ON)

# Pin external dependencies with FetchContent:
# include(FetchContent)
# FetchContent_Declare(
#   mylib
#   GIT_REPOSITORY https://github.com/org/mylib.git
#   GIT_TAG v1.2.3
# )
# FetchContent_MakeAvailable(mylib)

# Verify downloads:
# file(DOWNLOAD
#   https://example.com/archive.tar.gz
#   ${CMAKE_BINARY_DIR}/archive.tar.gz
#   EXPECTED_HASH SHA256=...
# )
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "CMake configs: none found"
        return (
            f"CMake configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "CMake analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            packages = ", ".join(info.packages[:8]) if info.packages else "none"
            externals = ", ".join(info.external_projects[:8]) if info.external_projects else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.packages)} package(s), {len(info.external_projects)} external dep(s)"
            )
            lines.append(f"    packages: {packages}")
            lines.append(f"    external deps: {externals}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
