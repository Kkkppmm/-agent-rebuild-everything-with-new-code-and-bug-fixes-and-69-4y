"""BunAnalyzer — audit bunfig.toml and bun.lock for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUN_CONFIG_NAMES = ("bunfig.toml",)
BUN_LOCK_NAMES = ("bun.lock", "bun.lockb")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
NPM_TOKEN_PATTERN = re.compile(r"[\"']?npm_[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
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
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.env\b)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
INSTALL_SCRIPTS_PATTERN = re.compile(
    r"(?:trustedDependencies|install\.scripts)\s*=\s*true",
    re.IGNORECASE,
)
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:tls|ssl)[._-]?(?:verify|rejectUnauthorized)\s*=\s*false",
    re.IGNORECASE,
)
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:github|gitlab|bitbucket):[^\"'\s]+#(?:main|master|HEAD|develop)\b|"
    r"git\+https?://[^\"'\s]+#(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)


@dataclass
class BunFinding:
    """A security or best-practice issue in a Bun configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BunInfo:
    """Parsed metadata from a Bun configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    registries: list[str] = field(default_factory=list)


@dataclass
class BunStats:
    """Aggregate statistics from Bun analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name in BUN_CONFIG_NAMES:
        return "bunfig"
    if name in BUN_LOCK_NAMES:
        return "lockfile"
    return "unknown"


def _is_bun_file(path: Path) -> bool:
    return path.name in (*BUN_CONFIG_NAMES, *BUN_LOCK_NAMES)


class BunAnalyzer:
    """Audit Bun configuration for security issues.

    Scans bunfig.toml and bun.lock for hardcoded tokens, insecure registry URLs,
    install script auto-execution, TLS verification bypass, credentials in git
    URLs, and dangerous lifecycle hooks.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root).resolve()
        self._findings: list[BunFinding] | None = None
        self._stats: BunStats | None = None
        self._infos: list[BunInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bun configuration paths found in the project."""
        paths: list[Path] = []
        for path in self.root.rglob("*"):
            if path.is_file() and _is_bun_file(path):
                paths.append(path)
        return sorted(set(paths))

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BunFinding],
        info: BunInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Bun config — use env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in Bun config — use BUN_CONFIG or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="aws_key",
                    severity="high",
                    message="AWS access key in Bun config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP registry URL — use HTTPS for package registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in git source URL — use bunfig scoped registry auth",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in config — avoid piping remote scripts to shell",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="sensitive_path",
                    severity="medium",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous script in Bun config — review install hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSTALL_SCRIPTS_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="install_scripts",
                    severity="medium",
                    message="install scripts enabled globally — only trust specific dependencies",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="tls_verify_off",
                    severity="high",
                    message="TLS verification disabled — package downloads are not authenticated",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="unpinned git dependency ref — pin to tags or commit SHAs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        registry_match = re.search(
            r"(?:registry|url)\s*=\s*[\"']?(\S+)[\"']?",
            stripped,
            re.IGNORECASE,
        )
        if registry_match:
            reg = registry_match.group(1).rstrip("\"',")
            if reg not in info.registries:
                info.registries.append(reg)

    def _analyze_file(self, path: Path) -> tuple[list[BunFinding], BunInfo]:
        findings: list[BunFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BunInfo(path=rel, file_kind=file_kind)

        info = BunInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if file_kind == "lockfile" and path.suffix == ".lockb":
            findings.append(
                BunFinding(
                    kind="binary_lockfile",
                    severity="low",
                    message="binary bun.lockb — prefer text bun.lock for reviewable diffs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[BunFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BunFinding] = []
        infos: list[BunInfo] = []
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
        self._stats = BunStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BunStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BunInfo]:
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
        """Scaffold a hardened bunfig.toml snippet."""
        return """\
[install]
# Only run lifecycle scripts for explicitly trusted packages
# trustedDependencies = ["esbuild"]

[install.scopes]
# Use env vars for tokens — never commit secrets
# "@myorg" = { token = "$NPM_TOKEN", url = "https://registry.npmjs.org/" }
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bun configs: none found"
        return (
            f"Bun configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bun analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            regs = ", ".join(info.registries[:4]) if info.registries else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): registries={regs}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
