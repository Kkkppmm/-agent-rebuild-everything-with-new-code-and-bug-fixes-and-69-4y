"""MiseAnalyzer — audit mise.toml, .mise.toml, and .tool-versions for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MISE_CONFIG_NAMES = (".mise.toml", "mise.toml")
TOOL_VERSIONS_NAMES = (".tool-versions", ".mise/.tool-versions")
MISE_DIRS = (".mise", "mise")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
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
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:ref|rev|branch|tag)\s*=\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:\?|&)ref=(?:main|master|HEAD|develop|trunk)\b|"
    r"github\.com/[^\"'\s]+(?:main|master|HEAD|develop|trunk)",
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
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*=\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
UNPINNED_TOOL_PATTERN = re.compile(
    r"=\s*[\"'](?:system|latest|\*|LATEST)[\"']|"
    r"^\s*[a-zA-Z0-9._-]+\s+(?:system|latest|\*)\s*$",
    re.IGNORECASE,
)
PLUGIN_URL_PATTERN = re.compile(
    r"(?:asdf|ubi|vfox):(?:https?://|git@)[^\s\"']+",
    re.IGNORECASE,
)
TOOL_ENTRY_PATTERN = re.compile(
    r"^[\"']?([a-zA-Z0-9._:-]+)[\"']?\s*=\s*[\"']?([^\"'\n#]+)[\"']?",
    re.IGNORECASE,
)
TASK_RUN_PATTERN = re.compile(
    r"^(?:run|depends|sources|outputs)\s*=",
    re.IGNORECASE,
)


@dataclass
class MiseFinding:
    """A security or best-practice issue in a mise configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MiseInfo:
    """Parsed metadata from a mise configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    tools: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)


@dataclass
class MiseStats:
    """Aggregate statistics from mise analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_mise_file(path: Path) -> bool:
    name = path.name
    if name in MISE_CONFIG_NAMES or name in TOOL_VERSIONS_NAMES:
        return True
    if name == ".tool-versions" and any(part in MISE_DIRS for part in path.parts):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in (".mise.toml", "mise.toml"):
        return "mise.toml"
    if name == ".tool-versions":
        return "tool-versions"
    return "unknown"


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith("#")


class MiseAnalyzer:
    """Audit mise configuration for security issues.

    Scans mise.toml, .mise.toml, and .tool-versions for hardcoded secrets in
    [env] blocks, insecure HTTP plugin URLs, credentials in git URLs, unpinned
    plugin refs, disabled TLS verification, dangerous task run scripts, curl
    piped to shell, and unpinned tool versions (system/latest/*).
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MiseFinding] | None = None
        self._stats: MiseStats | None = None
        self._infos: list[MiseInfo] | None = None

    def configs(self) -> list[Path]:
        """Return mise configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_mise_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[MiseFinding],
        info: MiseInfo,
        in_env_section: bool,
        in_task_section: bool,
    ) -> tuple[bool, bool]:
        if _is_comment_line(line):
            return in_env_section, in_task_section

        stripped = line.strip()

        if stripped == "[env]" or stripped.startswith("[env."):
            in_env_section = True
            in_task_section = False
        elif stripped.startswith("[tasks.") or stripped.startswith("[task."):
            in_task_section = True
            in_env_section = False
        elif stripped.startswith("[") and stripped.endswith("]"):
            in_env_section = False
            in_task_section = False

        if file_kind == "tool-versions":
            tool_match = re.match(r"^([a-zA-Z0-9._-]+)\s+(.+)$", stripped)
            if tool_match:
                info.tools.append(tool_match.group(1))
                version = tool_match.group(2).strip()
                if UNPINNED_TOOL_PATTERN.search(version) or version in ("system", "latest", "*"):
                    findings.append(
                        MiseFinding(
                            kind="unpinned_tool",
                            severity="low",
                            message="unpinned tool version — pin to explicit semver for reproducibility",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
        else:
            tool_match = TOOL_ENTRY_PATTERN.match(stripped)
            if tool_match and not stripped.startswith("[") and "=" in stripped:
                tool_name = tool_match.group(1)
                tool_version = tool_match.group(2).strip()
                if tool_name not in ("description", "min_version", "experimental"):
                    info.tools.append(tool_name)
                    if UNPINNED_TOOL_PATTERN.search(stripped) or tool_version in (
                        "system",
                        "latest",
                        "*",
                    ):
                        findings.append(
                            MiseFinding(
                                kind="unpinned_tool",
                                severity="low",
                                message="unpinned tool version — pin to explicit semver for reproducibility",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )

            if TASK_RUN_PATTERN.match(stripped):
                task_name = stripped.split("=")[0].strip()
                if task_name not in info.tasks:
                    info.tasks.append(task_name)

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or (in_env_section and ENV_SECRET_PATTERN.search(stripped))
        ):
            findings.append(
                MiseFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in mise config — use mise env files or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in mise config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for plugin sources and downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line) or (
            PLUGIN_URL_PATTERN.search(line) and UNPINNED_GIT_REF_PATTERN.search(line)
        ):
            findings.append(
                MiseFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="plugin or git ref pinned to moving branch — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in mise config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and (in_task_section or "run" in stripped.lower()):
            findings.append(
                MiseFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in mise task — review run scripts for privilege escalation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PLUGIN_URL_PATTERN.search(line) and INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="insecure_plugin",
                    severity="medium",
                    message="insecure HTTP plugin source — use HTTPS git URLs for mise plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return in_env_section, in_task_section

    def _analyze_file(self, path: Path) -> tuple[list[MiseFinding], MiseInfo]:
        findings: list[MiseFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MiseInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = MiseInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)
        in_env_section = False
        in_task_section = False

        for lineno, line in enumerate(raw_lines, start=1):
            in_env_section, in_task_section = self._scan_line(
                line,
                lineno,
                rel,
                file_kind,
                findings,
                info,
                in_env_section,
                in_task_section,
            )

        return findings, info

    def analyze(self) -> list[MiseFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MiseFinding] = []
        infos: list[MiseInfo] = []
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
        self._stats = MiseStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MiseStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MiseInfo]:
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
        """Scaffold a hardened mise.toml snippet with secure defaults."""
        return """\
# mise.toml — hardened defaults for mise projects
min_version = "2024.1.1"

[tools]
node = "20.10.0"
python = "3.12.0"
# Pin plugins to HTTPS git URLs with explicit tags/commits
# "go:asdf:https://github.com/asdf-community/asdf-golang.git" = "1.21.5"

[env]
# Store secrets via mise env files or CI — never commit credentials:
# _.file = ".env.local"  # gitignored
# API_KEY = "{{ env.API_KEY }}"

[tasks.setup]
run = "mise install"
# Avoid curl | sh — vendor scripts with checksum verification

[settings]
# Keep TLS verification enabled (default)
# experimental = false
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Mise configs: none found"
        return (
            f"Mise configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Mise analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tools = ", ".join(info.tools[:8]) if info.tools else "none"
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.tools)} tool(s), {len(info.tasks)} task field(s)"
            )
            lines.append(f"    tools: {tools}")
            lines.append(f"    tasks: {tasks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
