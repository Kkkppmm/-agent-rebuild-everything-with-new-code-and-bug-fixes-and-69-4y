"""DirenvAnalyzer — audit .envrc and direnv.toml for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DIRENV_CONFIG_NAMES = (".envrc", ".envrc.local", "direnv.toml")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
EXPORT_SECRET_PATTERN = re.compile(
    r"^export\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*="
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example|\.local)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
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
DOTENV_PATTERN = re.compile(r"^\s*(?:dotenv|dotenv_if_exists)\b", re.IGNORECASE)
SOURCE_ENV_PATTERN = re.compile(
    r"^\s*(?:source_env|source_up|source_up_if_exists)\b",
    re.IGNORECASE,
)
WATCH_PATTERN = re.compile(r"^\s*(?:watch_file|watch_dir)\b", re.IGNORECASE)
PATH_ADD_PATTERN = re.compile(r"^\s*(?:PATH_add|path_add)\b", re.IGNORECASE)
USE_NIX_PATTERN = re.compile(r"^\s*use\s+(?:nix|flake)\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"^\s*eval\b", re.IGNORECASE)
LOAD_PREFIX_PATTERN = re.compile(r"^\s*load_prefix\b", re.IGNORECASE)
STRICT_ENV_OFF_PATTERN = re.compile(
    r"(?:^|\s)STRICT_ENV\s*=\s*(?:0|false|no)|"
    r"strict_env\s*=\s*(?:false|0|no)",
    re.IGNORECASE,
)
UNPINNED_NIX_REF_PATTERN = re.compile(
    r"(?:branch|ref|rev|tag)\s*[=:]\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:\?|&)ref=(?:main|master|HEAD|develop|trunk)\b",
    re.IGNORECASE,
)
WORLD_WRITABLE_PATH_PATTERN = re.compile(
    r"(?:PATH_add|path_add|load_prefix)\s+[\"']?(?:/tmp|/var/tmp|\./)[\"']?",
    re.IGNORECASE,
)
LAYOUT_PATTERN = re.compile(r"^\s*layout\s+([a-zA-Z0-9_-]+)", re.IGNORECASE)


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
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DirenvInfo:
    """Parsed metadata about a direnv configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    layouts: list[str] = field(default_factory=list)
    dotenv_files: list[str] = field(default_factory=list)
    watch_targets: list[str] = field(default_factory=list)
    use_hooks: list[str] = field(default_factory=list)


@dataclass
class DirenvStats:
    """Aggregate direnv analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_direnv_file(path: Path) -> bool:
    """Return True if the path looks like a direnv configuration file."""
    return path.name in DIRENV_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    if path.name == "direnv.toml":
        return "toml"
    if path.name.endswith(".local"):
        return "envrc-local"
    return "envrc"


def _is_comment_line(line: str, file_kind: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if file_kind == "toml":
        return stripped.startswith("#")
    return stripped.startswith("#")


class DirenvAnalyzer:
    """Audit direnv configuration for security issues.

    Scans .envrc, .envrc.local, and direnv.toml for hardcoded secrets in
    export statements, dotenv loading of credential files, watch_file on secrets,
    insecure source_env/source_up URLs, disabled strict_env, curl piped to
    shell in eval/use hooks, dangerous PATH_add paths, unpinned use nix/flake
    refs, and sensitive load_prefix targets.
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

        layout_match = LAYOUT_PATTERN.match(stripped)
        if layout_match:
            layout_name = layout_match.group(1)
            if layout_name not in info.layouts:
                info.layouts.append(layout_name)

        if DOTENV_PATTERN.match(stripped):
            parts = stripped.split()
            if len(parts) > 1:
                info.dotenv_files.append(parts[1].strip("\"'"))

        if WATCH_PATTERN.match(stripped):
            parts = stripped.split()
            if len(parts) > 1:
                info.watch_targets.append(parts[1].strip("\"'"))

        if USE_NIX_PATTERN.match(stripped):
            info.use_hooks.append(stripped)

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or EXPORT_SECRET_PATTERN.search(stripped)
        ):
            findings.append(
                DirenvFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in direnv config — use direnv private files or CI secret stores",
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

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for source_env and download hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or token env vars",
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

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive path reference — avoid loading or watching credential files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep certificate validation enabled",
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
                    message="dangerous shell command in direnv config — review eval and hook scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_ENV_OFF_PATTERN.search(line):
            findings.append(
                DirenvFinding(
                    kind="strict_env_disabled",
                    severity="medium",
                    message="strict_env disabled — keep strict_env enabled to block inherited secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOTENV_PATTERN.match(stripped) and SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="dotenv_sensitive",
                    severity="high",
                    message="dotenv loading credential file — use gitignored .env.local with direnv private",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WATCH_PATTERN.match(stripped) and SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="watch_sensitive",
                    severity="medium",
                    message="watch_file/watch_dir on credential path — avoid watching secret files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SOURCE_ENV_PATTERN.match(stripped) and INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="insecure_source",
                    severity="medium",
                    message="source_env/source_up from insecure HTTP — use HTTPS or local paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if USE_NIX_PATTERN.match(stripped) and UNPINNED_NIX_REF_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="unpinned_nix_ref",
                    severity="medium",
                    message="use nix/flake ref pinned to moving branch — pin flake.lock or nixpkgs revision",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WORLD_WRITABLE_PATH_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="writable_path_add",
                    severity="medium",
                    message="PATH_add/load_prefix on world-writable path — avoid /tmp or relative paths in PATH",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.match(stripped) and not stripped.startswith("eval \"$(direnv"):
            findings.append(
                DirenvFinding(
                    kind="eval_usage",
                    severity="low",
                    message="eval in .envrc — prefer direnv builtins over arbitrary eval for hook logic",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOAD_PREFIX_PATTERN.match(stripped) and SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                DirenvFinding(
                    kind="load_prefix_sensitive",
                    severity="high",
                    message="load_prefix on sensitive directory — avoid exposing credential directories",
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
# Keep strict_env enabled (default) — do not set STRICT_ENV=0

layout python

# Store secrets in gitignored files loaded via direnv private:
# dotenv_if_exists .env.local

# Pin Nix flakes via flake.lock — avoid unpinned refs:
# use flake

# Avoid curl | sh — vendor scripts with checksum verification
# Avoid PATH_add on /tmp or relative writable paths
# Avoid watch_file on .env or credential files
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
            layouts = ", ".join(info.layouts[:8]) if info.layouts else "none"
            dotenv = ", ".join(info.dotenv_files[:8]) if info.dotenv_files else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.layouts)} layout(s), {len(info.dotenv_files)} dotenv file(s)"
            )
            lines.append(f"    layouts: {layouts}")
            lines.append(f"    dotenv: {dotenv}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
