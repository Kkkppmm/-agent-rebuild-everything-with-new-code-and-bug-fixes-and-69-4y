"""MiseAnalyzer — audit .mise.toml, .tool-versions, and mise.lock for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MISE_FILE_NAMES = (".mise.toml", "mise.toml", ".rtx.toml", "rtx.toml")
TOOL_VERSIONS_NAMES = (".tool-versions", ".tool-versions.local")
MISE_LOCK_NAMES = ("mise.lock",)
MISE_DIRS = (".mise",)
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
UNPINNED_VERSION_PATTERN = re.compile(
    r"(?:^|\s)(?:nodejs|node|python|ruby|go|java|rust|deno|bun|terraform|kubectl|"
    r"helm|docker|awscli|gh|pnpm|yarn|npm|poetry|uv|pipx)\s+"
    r"(?:latest|system|LATEST|SYSTEM|\*|head|HEAD|master|main)\b",
    re.IGNORECASE,
)
UNPINNED_TOML_VERSION_PATTERN = re.compile(
    r"=\s*[\"'](?:latest|system|LATEST|SYSTEM|\*|head|HEAD|master|main)[\"']",
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
    r"(?:MISE_.*SSL|ssl_verify|verify_ssl|GIT_SSL_NO_VERIFY)[\"']?\s*[=:]\s*"
    r"(?:[\"']?(?:true|1|on|True|ON)[\"']?)\b|"
    r"curl\s+[^\n]*--insecure\b|"
    r"curl\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
GIT_PLUGIN_PATTERN = re.compile(
    r"(?:git|plugin)\s*=\s*[\"']git\+?https?://[^\"']+[\"']|"
    r"\"git\+https?://[^\"']+\"",
    re.IGNORECASE,
)
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:ref|rev|branch|tag)\s*=\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:\?|&)ref=(?:main|master|HEAD|develop|trunk)\b|"
    r"git\+https?://[^\"']*(?:main|master|HEAD|develop|trunk)[\"']",
    re.IGNORECASE,
)
MISE_ENV_SECRET_PATTERN = re.compile(
    r"(?:\[env\]|^\s*[A-Z][A-Z0-9_]*\s*=).*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|"
    r"CREDENTIAL|PRIVATE[_-]?KEY)\s*=\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
TOOL_VERSION_PATTERN = re.compile(
    r"^([a-zA-Z0-9._-]+)\s+([^\s#]+)",
)
TOML_TOOL_PATTERN = re.compile(
    r'^([a-zA-Z0-9._-]+)\s*=\s*["\']([^"\']+)["\']',
)
TASK_RUN_PATTERN = re.compile(
    r'run\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
HOOK_SCRIPT_PATTERN = re.compile(
    r'(?:preinstall|postinstall|enter|exit)\s*=\s*["\']([^"\']+)["\']',
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
    plugins: list[str] = field(default_factory=list)


@dataclass
class MiseStats:
    """Aggregate statistics from mise analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_mise_file(path: Path) -> bool:
    name = path.name
    if name in MISE_FILE_NAMES or name in TOOL_VERSIONS_NAMES or name in MISE_LOCK_NAMES:
        return True
    if path.parent.name in MISE_DIRS and path.suffix in (".toml", ".lock"):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in (".mise.toml", "mise.toml"):
        return "mise.toml"
    if name in (".rtx.toml", "rtx.toml"):
        return "rtx.toml"
    if name in TOOL_VERSIONS_NAMES:
        return "tool-versions"
    if name == "mise.lock":
        return "mise.lock"
    return "unknown"


def _is_comment_line(line: str, file_kind: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if file_kind == "tool-versions":
        return stripped.startswith("#")
    return stripped.startswith("#") or stripped.startswith("//")


class MiseAnalyzer:
    """Audit mise/asdf runtime version configuration for security issues.

    Scans .mise.toml, .tool-versions, mise.lock, and legacy .rtx.toml for
    hardcoded secrets, insecure HTTP plugin URLs, credentials in git URLs,
    unpinned tool versions, disabled TLS verification, and dangerous task scripts.
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
    ) -> None:
        if _is_comment_line(line, file_kind):
            return

        if file_kind == "tool-versions":
            tool_match = TOOL_VERSION_PATTERN.match(line.strip())
            if tool_match:
                info.tools.append(f"{tool_match.group(1)} {tool_match.group(2)}")
        else:
            tool_match = TOML_TOOL_PATTERN.match(line.strip())
            if tool_match and not line.strip().startswith("["):
                info.tools.append(f"{tool_match.group(1)} {tool_match.group(2)}")

        if GIT_PLUGIN_PATTERN.search(line):
            info.plugins.append(line.strip()[:80])

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or MISE_ENV_SECRET_PATTERN.search(line)
        ):
            findings.append(
                MiseFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in mise config — use env vars or a secrets manager",
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
                    message="AWS access key in mise config — use credential helpers",
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

        if UNPINNED_VERSION_PATTERN.search(line) or UNPINNED_TOML_VERSION_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="unpinned_version",
                    severity="medium",
                    message="unpinned tool version — pin to a specific version for reproducibility",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                MiseFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="git ref pinned to moving branch — pin to commit SHA or version tag",
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
                    message="curl/wget piped to shell — vendor scripts with checksum verification",
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
                    message="sensitive host path reference — avoid bundling credentials in config",
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
                    message="TLS verification disabled — keep SSL verification enabled for downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        task_match = TASK_RUN_PATTERN.search(line) or HOOK_SCRIPT_PATTERN.search(line)
        if task_match and DANGEROUS_SHELL_PATTERN.search(task_match.group(1)):
            findings.append(
                MiseFinding(
                    kind="dangerous_task_script",
                    severity="high",
                    message="dangerous command in mise task/hook — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[MiseFinding], MiseInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[MiseFinding] = []
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MiseInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = MiseInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

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
            configs=len({p.parent for p in paths} if paths else []),
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
        """Scaffold a hardened .mise.toml snippet with secure defaults."""
        return """\
# Secure .mise.toml — pin tool versions, load secrets from the environment
[tools]
node = "22.12.0"
python = "3.12.8"
terraform = "1.10.3"

[env]
# Load secrets from the environment, never hardcode tokens here
# DATABASE_URL = { value = "${DATABASE_URL}", tools = true }

[settings]
# Keep TLS verification enabled for plugin downloads
# experimental = true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Mise configs: none found"
        return (
            f"Mise configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Mise analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tools = ", ".join(info.tools[:8]) if info.tools else "none"
            plugins = ", ".join(info.plugins[:4]) if info.plugins else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.tools)} tool(s), {len(info.plugins)} plugin(s)"
            )
            lines.append(f"      tools: {tools}")
            if info.plugins:
                lines.append(f"      plugins: {plugins}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
