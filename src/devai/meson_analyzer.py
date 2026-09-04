"""MesonAnalyzer — audit meson.build, wrap files, and Meson options for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MESON_BUILD_NAME = "meson.build"
MESON_OPTIONS_NAME = "meson_options.txt"
MESON_WRAP_SUFFIX = ".wrap"
MESON_WRAP_DIR = "subprojects"
MESON_CROSS_DIRS = ("cross", "native", "meson/cross", "meson/native")
MESON_CROSS_SUFFIXES = (".ini", ".txt")
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
UNPINNED_REVISION_PATTERN = re.compile(
    r"(?:revision|branch)\s*=\s*(?:head|HEAD|main|master|develop|trunk)\b",
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
RUN_COMMAND_PATTERN = re.compile(r"\brun_command\s*\(", re.IGNORECASE)
DEPENDENCY_PATTERN = re.compile(
    r"\bdependency\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
SUBPROJECT_PATTERN = re.compile(
    r"\bsubproject\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
MESON_OPTION_SECRET_PATTERN = re.compile(
    r"option\s*\(\s*['\"][^'\"]*(?:password|secret|token|api[_-]?key|credential)[^'\"]*['\"]"
    r"[^)]*value\s*:\s*['\"][^\"'\s${}][^\"']*['\"]",
    re.IGNORECASE,
)
MESON_SET_SECRET_PATTERN = re.compile(
    r"(?:option|set_variable|configuration_data\s*\(\)\.set)\s*\(\s*"
    r"['\"][^'\"]*(?:password|secret|token|api[_-]?key|credential)[^'\"]*['\"]\s*,\s*"
    r"['\"][^\"'\s${}][^\"']*['\"]",
    re.IGNORECASE,
)
WRAP_FILE_SECTION_PATTERN = re.compile(r"^\s*\[wrap-file\]\s*$", re.IGNORECASE | re.MULTILINE)
SOURCE_URL_PATTERN = re.compile(r"^\s*source_url\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
SOURCE_HASH_PATTERN = re.compile(r"^\s*source_hash\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class MesonFinding:
    """A security or best-practice issue in a Meson configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MesonInfo:
    """Parsed metadata from a Meson configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    dependencies: list[str] = field(default_factory=list)
    subprojects: list[str] = field(default_factory=list)


@dataclass
class MesonStats:
    """Aggregate statistics from Meson analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_meson_file(path: Path) -> bool:
    if path.name == MESON_BUILD_NAME or path.name == MESON_OPTIONS_NAME:
        return True
    if path.suffix == MESON_WRAP_SUFFIX and MESON_WRAP_DIR in path.parts:
        return True
    if path.suffix in MESON_CROSS_SUFFIXES:
        if any(part in MESON_CROSS_DIRS for part in path.parts):
            return True
        if path.parent.name in ("cross", "native"):
            return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == MESON_BUILD_NAME:
        return "meson.build"
    if name == MESON_OPTIONS_NAME:
        return "meson_options"
    if path.suffix == MESON_WRAP_SUFFIX:
        return "wrap"
    if path.suffix in MESON_CROSS_SUFFIXES:
        return "cross"
    return "unknown"


class MesonAnalyzer:
    """Audit Meson configuration for security issues.

    Scans meson.build, meson_options.txt, subprojects/*.wrap, and cross/native
    files for hardcoded secrets, insecure HTTP URLs, credentials in git URLs,
    unpinned wrap revisions, dangerous run_command calls, and wrap-file downloads
    without source_hash verification.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MesonFinding] | None = None
        self._stats: MesonStats | None = None
        self._infos: list[MesonInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Meson configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_meson_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MesonFinding],
        info: MesonInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        dep_match = DEPENDENCY_PATTERN.search(stripped)
        if dep_match:
            info.dependencies.append(dep_match.group(1))

        sub_match = SUBPROJECT_PATTERN.search(stripped)
        if sub_match:
            info.subprojects.append(sub_match.group(1))

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or MESON_SET_SECRET_PATTERN.search(line)
            or MESON_OPTION_SECRET_PATTERN.search(line)
        ):
            findings.append(
                MesonFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Meson config — use environment variables or meson options",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MesonFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Meson config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MesonFinding(
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
                MesonFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_REVISION_PATTERN.search(line):
            findings.append(
                MesonFinding(
                    kind="unpinned_wrap_revision",
                    severity="medium",
                    message="wrap dependency pinned to moving ref — pin revision to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MesonFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Meson — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                MesonFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and RUN_COMMAND_PATTERN.search(line):
            findings.append(
                MesonFinding(
                    kind="dangerous_run_command",
                    severity="high",
                    message="dangerous command in run_command — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _check_wrap_hashes(
        self,
        text: str,
        rel: str,
        findings: list[MesonFinding],
    ) -> None:
        if not WRAP_FILE_SECTION_PATTERN.search(text):
            return
        for match in SOURCE_URL_PATTERN.finditer(text):
            url = match.group(1).strip()
            if not url.startswith(("http://", "https://")):
                continue
            start = match.start()
            lineno = text[:start].count("\n") + 1
            section_start = text.rfind("[", 0, start)
            section_end = text.find("\n[", start)
            if section_end == -1:
                section_end = len(text)
            section = text[section_start:section_end]
            if SOURCE_HASH_PATTERN.search(section):
                continue
            findings.append(
                MesonFinding(
                    kind="wrap_download_without_hash",
                    severity="medium",
                    message="wrap-file source_url without source_hash — verify download integrity",
                    path=rel,
                    lineno=lineno,
                    line=match.group(0).strip(),
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[MesonFinding], MesonInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[MesonFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MesonInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = MesonInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if path.suffix == MESON_WRAP_SUFFIX:
            self._check_wrap_hashes(text, rel, findings)

        return findings, info

    def analyze(self) -> list[MesonFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MesonFinding] = []
        infos: list[MesonInfo] = []
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
        self._stats = MesonStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MesonStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MesonInfo]:
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
        """Scaffold a hardened Meson snippet with secure defaults."""
        return """\
# meson.build — hardened defaults for Meson projects
# Store secrets via environment variables or meson_options.txt:
#   option('api_token', type: 'string', value: '', description: 'API token from env')

project('secure-demo', 'c',
  meson_version: '>=0.59.0',
  default_options: ['warning_level=2', 'werror=true'],
)

# Pin wrap dependencies in subprojects/*.wrap:
# [wrap-git]
# url = https://github.com/org/mylib.git
# revision = v1.2.3

# Verify wrap-file downloads:
# [wrap-file]
# source_url = https://example.com/archive.tar.gz
# source_filename = archive.tar.gz
# source_hash = sha256:abcdef...
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Meson configs: none found"
        return (
            f"Meson configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Meson analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            subs = ", ".join(info.subprojects[:8]) if info.subprojects else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.subprojects)} subproject(s)"
            )
            lines.append(f"      dependencies: {deps}")
            lines.append(f"      subprojects: {subs}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
