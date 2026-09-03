"""TowncrierAnalyzer — audit Towncrier changelog configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("towncrier.toml",)
PYPROJECT_NAME = "pyproject.toml"

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
TOWNCRIER_SECTION_PATTERN = re.compile(r"^\[tool\.towncrier\]", re.IGNORECASE)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"[\"'](?:\.\./|\.\.\\|/etc/|/tmp/|\.ssh/|~/)",
    re.IGNORECASE,
)
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:directory|filename|template|package)\s*=\s*[\"']/[^\"']*[\"']",
    re.IGNORECASE,
)
FORMAT_SHELL_PATTERN = re.compile(
    r"(?:title_format|issue_format)\s*=\s*[\"'][^\"']*(?:\$\(|`[^`]*\$\(|&&|\|\|)[^\"']*[\"']",
    re.IGNORECASE,
)
SINGLE_FILE_FALSE_PATTERN = re.compile(r"single_file\s*=\s*false\b", re.IGNORECASE)
PATH_KEY_PATTERN = re.compile(
    r"^\s*(?:directory|filename|template|package)\s*=",
    re.IGNORECASE,
)


@dataclass
class TowncrierFinding:
    """A security or best-practice issue in a Towncrier configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TowncrierInfo:
    """Parsed metadata about a Towncrier configuration file."""

    path: str
    lines: int = 0
    directory: str = ""
    filename: str = ""
    template: str = ""
    single_file: bool | None = None


@dataclass
class TowncrierStats:
    """Aggregate Towncrier analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class TowncrierAnalyzer:
    """Audit Towncrier configs for changelog path traversal, secrets, and unsafe formats.

    Scans pyproject.toml [tool.towncrier] and towncrier.toml for hardcoded secrets,
    path traversal in directory/filename/template, insecure HTTP URLs, SCM credentials,
    shell metacharacters in format strings, and single_file=false risks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TowncrierFinding] | None = None
        self._stats: TowncrierStats | None = None
        self._infos: list[TowncrierInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Towncrier configuration paths found in the project."""
        found: list[Path] = []
        pyproject = self.root / PYPROJECT_NAME
        if pyproject.is_file() and self._has_towncrier_section(pyproject):
            found.append(pyproject)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _has_towncrier_section(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "[tool.towncrier" in text.lower()

    def _record_path_value(self, line: str, info: TowncrierInfo) -> None:
        for key in ("directory", "filename", "template", "package"):
            match = re.search(
                rf"{key}\s*=\s*[\"']([^\"']+)[\"']",
                line,
                re.IGNORECASE,
            )
            if match:
                value = match.group(1)
                if key == "directory":
                    info.directory = value
                elif key == "filename":
                    info.filename = value
                elif key == "template":
                    info.template = value

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TowncrierFinding],
        info: TowncrierInfo,
        in_towncrier_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if in_towncrier_section:
            self._record_path_value(line, info)

            if SINGLE_FILE_FALSE_PATTERN.search(line):
                info.single_file = False
                findings.append(
                    TowncrierFinding(
                        kind="single_file_disabled",
                        severity="low",
                        message="single_file=false writes fragments — ensure directory permissions are restrictive",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PATH_KEY_PATTERN.match(stripped) and PATH_TRAVERSAL_PATTERN.search(line):
                findings.append(
                    TowncrierFinding(
                        kind="path_traversal",
                        severity="high",
                        message="path contains traversal or sensitive location — keep changelog paths inside the repo",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ABSOLUTE_PATH_PATTERN.search(line):
                findings.append(
                    TowncrierFinding(
                        kind="absolute_path",
                        severity="medium",
                        message="absolute path in Towncrier config — prefer repo-relative paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FORMAT_SHELL_PATTERN.search(line):
                findings.append(
                    TowncrierFinding(
                        kind="format_shell_metachar",
                        severity="medium",
                        message="title_format/issue_format contains shell metacharacters — keep formats static",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if not in_towncrier_section:
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get|\{[A-Z_]+\}", line, re.IGNORECASE):
                findings.append(
                    TowncrierFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Towncrier config — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Towncrier config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Towncrier config — use HTTPS for issue links and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in Towncrier config — review changelog automation carefully",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in Towncrier config — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TowncrierFinding], TowncrierInfo]:
        findings: list[TowncrierFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TowncrierInfo(path=rel)

        info = TowncrierInfo(path=rel, lines=len(raw_lines))
        in_towncrier_section = path.name == "towncrier.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if TOWNCRIER_SECTION_PATTERN.match(stripped):
                in_towncrier_section = True
            elif stripped.startswith("[") and not TOWNCRIER_SECTION_PATTERN.match(stripped):
                in_towncrier_section = False

            self._scan_line(line, lineno, rel, findings, info, in_towncrier_section)

        return findings, info

    def analyze(self) -> list[TowncrierFinding]:
        """Scan Towncrier config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TowncrierFinding] = []
        infos: list[TowncrierInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = TowncrierStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TowncrierStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TowncrierInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened pyproject.toml [tool.towncrier] template."""
        return """\
# Generated by DevAI TowncrierAnalyzer
# Add this section to pyproject.toml

[tool.towncrier]
package = "myproject"
directory = "changelog.d"
filename = "CHANGELOG.md"
template = "changelog.d/template.md"
title_format = "## [{version}] - {project_date}"
issue_format = "`#{issue} <https://github.com/org/repo/issues/{issue}>`_"
single_file = true
underlines = "-~^"
# Keep paths repo-relative; use HTTPS in issue_format links
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Towncrier configs: none found"
        return (
            f"Towncrier configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Towncrier analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            directory = info.directory or "unspecified"
            filename = info.filename or "unspecified"
            single = "false" if info.single_file is False else "true/unspecified"
            lines.append(f"  - {info.path}: directory={directory}, filename={filename}, single_file={single}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
