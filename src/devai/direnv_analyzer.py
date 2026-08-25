"""DirenvAnalyzer — audit .envrc and direnv.toml for environment security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ENVRC_NAMES = (".envrc", ".envrc.local")
DIRENV_CONFIG_NAMES = ("direnv.toml", ".config/direnv/direnv.toml")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
EXPORT_SECRET_PATTERN = re.compile(
    r"export\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
REMOTE_SOURCE_PATTERN = re.compile(
    r"(?:source_env|source_url|fetchurl)\s+[\"']?(?:https?://|git@)[^\"'\s]+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
DOTENV_ALLOW_PATTERN = re.compile(
    r"dotenv_if_exists\s+[\"']?\.env[\"']?",
    re.IGNORECASE,
)
PATH_ADD_SENSITIVE_PATTERN = re.compile(
    r"PATH_add\s+[\"']?(?:/usr/local/bin|\$HOME/\.local/bin)[\"']?",
    re.IGNORECASE,
)
DISABLE_STRICT_PATTERN = re.compile(
    r"(?:strict_env|warn_timeout)\s*=\s*false",
    re.IGNORECASE,
)


@dataclass
class DirenvFinding:
    """A security or best-practice issue in a direnv configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DirenvInfo:
    """Parsed metadata from a direnv configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    exports: list[str] = field(default_factory=list)
    layouts: list[str] = field(default_factory=list)


@dataclass
class DirenvStats:
    """Aggregate statistics from direnv analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_direnv_file(path: Path) -> bool:
    name = path.name
    if name in ENVRC_NAMES:
        return True
    if name == "direnv.toml":
        return True
    parts = path.parts
    if name == "direnv.toml" and ".config" in parts and "direnv" in parts:
        return True
    return False


def _file_kind(path: Path) -> str:
    if path.name in ENVRC_NAMES:
        return "envrc"
    return "direnv.toml"


def _is_comment_line(line: str, file_kind: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if file_kind == "envrc":
        return stripped.startswith("#")
    return stripped.startswith("#") or stripped.startswith(";")


class DirenvAnalyzer:
    """Audit direnv configuration for security issues.

    Scans .envrc and direnv.toml for hardcoded secrets, remote source_env URLs,
    curl piped to shell, dangerous shell commands, dotenv loading of .env files,
    and disabled strict environment checks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DirenvFinding] | None = None
        self._stats: DirenvStats | None = None
        self._infos: list[DirenvInfo] | None = None

    def configs(self) -> list[Path]:
        """Return direnv configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_direnv_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[DirenvFinding],
        info: DirenvInfo,
    ) -> None:
        if _is_comment_line(line, file_kind):
            return

        stripped = line.strip()

        export_match = re.match(r"export\s+([A-Z0-9_]+)\s*=", stripped)
        if export_match:
            info.exports.append(export_match.group(1))

        layout_match = re.match(r"layout\s+(\w+)", stripped)
        if layout_match:
            info.layouts.append(layout_match.group(1))

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or EXPORT_SECRET_PATTERN.search(stripped)
        ):
            findings.append(
                DirenvFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in direnv config — use .env.local (gitignored) or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in direnv config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_SOURCE_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="remote_source",
                    severity="high",
                    message="remote source_env/source_url — avoid loading env from untrusted URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for remote environment sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in direnv config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in direnv config — review for privilege escalation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="sensitive_path",
                    severity="medium",
                    message="sensitive host path reference — avoid bundling credentials in envrc",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOTENV_ALLOW_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="dotenv_load",
                    severity="medium",
                    message="loading .env via dotenv_if_exists — ensure .env is gitignored and never committed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_STRICT_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="strict_disabled",
                    severity="low",
                    message="strict direnv checks disabled — keep strict_env enabled for safer env loading",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[DirenvFinding], DirenvInfo]:
        findings: list[DirenvFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DirenvInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = DirenvInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

        return findings, info

    def analyze(self) -> list[DirenvFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DirenvFinding] = []
        infos: list[DirenvInfo] = []
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
        self._stats = DirenvStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DirenvStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DirenvInfo]:
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
        """Scaffold a hardened .envrc snippet with secure defaults."""
        return """\
# .envrc — hardened defaults for direnv projects
# Store secrets in .env.local (gitignored), not in .envrc

layout python

# Load local overrides only — never commit secrets:
# dotenv_if_exists .env.local

# Use watch_file for dependency tracking instead of remote sources
watch_file pyproject.toml

# Keep strict env checks enabled (default in direnv.toml)
# strict_env = true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Direnv configs: none found"
        return (
            f"Direnv configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Direnv analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            exports = ", ".join(info.exports[:8]) if info.exports else "none"
            layouts = ", ".join(info.layouts[:8]) if info.layouts else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"exports={exports}, layouts={layouts}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
