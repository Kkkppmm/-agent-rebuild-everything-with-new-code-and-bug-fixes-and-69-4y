"""BunAnalyzer — audit bunfig.toml, bun.lock, and bun.lockb for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUNFIG_NAMES = ("bunfig.toml", "bunfig.json")
BUN_LOCK_NAMES = ("bun.lock", "bun.lockb")
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
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"[\"'](?:\*|latest|LATEST)[\"']|"
    r"(?:git\+|github:|gitlab:)[^\s\"']+#(?:main|master|HEAD|develop)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:tls\s*=\s*false|rejectUnauthorized\s*:\s*false|"
    r"strictSSL\s*=\s*false|cafile\s*=\s*/dev/null)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
REGISTRY_URL_PATTERN = re.compile(
    r"(?:registry|install\.registry|publishConfig\.registry)\s*[=:]\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
TRUST_ALL_PATTERN = re.compile(
    r"(?:trust\s*=\s*true|--trust\b|trustedDependencies\s*=\s*\[)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
ALLOW_SCRIPTS_PATTERN = re.compile(
    r"(?:ignoreScripts\s*=\s*false|run\.shell\s*=)",
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
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BunInfo:
    """Parsed metadata about a Bun configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    registries: list[str] = field(default_factory=list)


@dataclass
class BunStats:
    """Aggregate Bun analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bun_file(path: Path) -> bool:
    """Return True if the path looks like a Bun configuration file."""
    return path.name in BUNFIG_NAMES or path.name in BUN_LOCK_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("bunfig"):
        return "bunfig"
    if name == "bun.lock":
        return "lock"
    if name == "bun.lockb":
        return "lockb"
    return "unknown"


class BunAnalyzer:
    """Audit Bun runtime and lockfile configuration for security issues.

    Scans bunfig.toml/json and bun.lock for hardcoded secrets, insecure
    registries, unpinned git dependencies, disabled TLS verification, broad
    trust settings, and dangerous install/run script patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BunFinding] | None = None
        self._stats: BunStats | None = None
        self._infos: list[BunInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bun configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_bun_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BunFinding], BunInfo]:
        findings: list[BunFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            if path.suffix == ".lockb":
                return findings, BunInfo(path=rel, file_kind="lockb")
            return findings, BunInfo(path=rel)

        raw_lines = text.splitlines()
        info = BunInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            registry_match = REGISTRY_URL_PATTERN.search(stripped)
            if registry_match:
                info.registries.append(registry_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BunFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Bun config — use env vars or Bun secrets",
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
                        message="AWS access key in Bun config — rotate and use env vars",
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
                        message="credentials embedded in git URL — use SSH keys or token env vars",
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
                        message="HTTP URL in Bun config — use HTTPS registries and sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    BunFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="TLS verification disabled — keep strict SSL for Bun installs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DYNAMIC_VERSION_PATTERN.search(line):
                findings.append(
                    BunFinding(
                        kind="unpinned_dependency",
                        severity="medium",
                        message="unpinned or floating dependency — pin versions or git refs to commits",
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
                        message="curl|wget piped to shell — verify scripts and use pinned installers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if TRUST_ALL_PATTERN.search(line):
                findings.append(
                    BunFinding(
                        kind="trust_all",
                        severity="medium",
                        message="broad Bun trust settings — restrict trustedDependencies to required packages",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if ALLOW_SCRIPTS_PATTERN.search(line):
                findings.append(
                    BunFinding(
                        kind="scripts_enabled",
                        severity="low",
                        message="install/run scripts enabled — use ignoreScripts in CI when possible",
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
                        message="dangerous shell pattern — review Bun run/install hooks",
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
                        message="sensitive path referenced — avoid exposing credential paths in Bun config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[BunFinding]:
        """Run analysis and return findings."""
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
            configs=len({p.parent for p in paths} if paths else []),
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
# bunfig.toml — secure defaults
[install]
registry = "https://registry.npmjs.org/"
exact = true
ignoreScripts = true

[install.scopes]
# "@myorg" = { token = "$NPM_TOKEN", url = "https://registry.npmjs.org/" }
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bun configs: none found"
        return (
            f"Bun configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bun analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            registries = ", ".join(info.registries[:4]) if info.registries else "default"
            lines.append(f"  - {info.path} ({info.file_kind}): registries={registries}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
