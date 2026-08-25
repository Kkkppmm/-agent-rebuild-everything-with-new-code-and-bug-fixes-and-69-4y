"""PnpmAnalyzer — audit pnpm-workspace.yaml, pnpm-lock.yaml, and .npmrc for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PNPM_WORKSPACE_NAMES = ("pnpm-workspace.yaml", "pnpm-workspace.yml")
PNPM_LOCK_NAMES = ("pnpm-lock.yaml", "pnpm-lock.yml")
PNPM_CONFIG_NAMES = (".npmrc", ".pnpmfile.cjs", ".pnpmfile.mjs")
PNPM_MARKER_PATTERN = re.compile(
    r"(?:^pnpm\.|shamefully-hoist|strict-peer-dependencies|auto-install-peers|"
    r"only-built-dependencies|store-dir|virtual-store-dir)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|_authToken|_auth)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PNPM_TOKEN_PATTERN = re.compile(r"[\"']?npm_[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
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
    r"(?:strict-ssl\s*=\s*false|strictSsl\s*:\s*false|"
    r"cafile\s*=\s*/dev/null|ca\s*=\s*null)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
REGISTRY_URL_PATTERN = re.compile(
    r"(?:registry|@scope:registry)\s*[=:]\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
HOIST_PATTERN = re.compile(
    r"(?:shamefully-hoist\s*=\s*true|public-hoist-pattern\s*=|hoist-pattern\s*=)",
    re.IGNORECASE,
)
TRUST_ALL_PATTERN = re.compile(
    r"(?:trust-policy\s*=\s*no-downgrade|trust-policy\s*=\s*off|"
    r"ignore-scripts\s*=\s*false)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)


@dataclass
class PnpmFinding:
    """A security or best-practice issue in a pnpm configuration file."""

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
class PnpmInfo:
    """Parsed metadata about a pnpm configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    packages: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)


@dataclass
class PnpmStats:
    """Aggregate pnpm analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pnpm_file(path: Path) -> bool:
    """Return True if the path looks like a pnpm configuration file."""
    name = path.name
    if name in PNPM_WORKSPACE_NAMES or name in PNPM_LOCK_NAMES:
        return True
    if name in PNPM_CONFIG_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if name != ".npmrc" or PNPM_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("pnpm-workspace"):
        return "workspace"
    if name.startswith("pnpm-lock"):
        return "lock"
    if name == ".npmrc":
        return "npmrc"
    if name.startswith(".pnpmfile"):
        return "pnpmfile"
    return "unknown"


class PnpmAnalyzer:
    """Audit pnpm workspace and config files for security issues.

    Scans pnpm-workspace.yaml, pnpm-lock.yaml, .npmrc, and .pnpmfile.* for
    hardcoded tokens, insecure registries, unpinned git dependencies, hoist
    bypasses, disabled script protections, and credentials in SCM URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PnpmFinding] | None = None
        self._stats: PnpmStats | None = None
        self._infos: list[PnpmInfo] | None = None

    def configs(self) -> list[Path]:
        """Return pnpm configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pnpm_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PnpmFinding], PnpmInfo]:
        findings: list[PnpmFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PnpmInfo(path=rel)

        raw_lines = text.splitlines()
        info = PnpmInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            pkg_match = re.search(r"^\s*-\s*['\"]?([^'\"]+)['\"]?\s*$", stripped)
            if pkg_match:
                info.packages.append(pkg_match.group(1))

            registry_match = REGISTRY_URL_PATTERN.search(stripped)
            if registry_match:
                info.registries.append(registry_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in pnpm config — use CI secrets or pnpm config env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if PNPM_TOKEN_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="npm/pnpm token in config — rotate and use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="aws_key",
                        severity="high",
                        message="AWS access key in pnpm config — rotate and use env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
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
                    PnpmFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="HTTP URL in pnpm config — use HTTPS registries and sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL verification disabled — keep strict-ssl enabled for registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DYNAMIC_VERSION_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
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
                    PnpmFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|wget piped to shell — verify scripts and use pinned installers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if HOIST_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="hoist_bypass",
                        severity="low",
                        message="hoist settings may weaken dependency isolation — review shamefully-hoist usage",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if TRUST_ALL_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="trust_policy",
                        severity="medium",
                        message="relaxed pnpm trust or script policy — enable ignore-scripts in CI when possible",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DANGEROUS_SCRIPT_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="dangerous_script",
                        severity="high",
                        message="dangerous shell pattern in pnpm hook — review lifecycle and pnpmfile scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive path referenced in pnpm config — avoid exposing credentials paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[PnpmFinding]:
        """Run analysis and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PnpmFinding] = []
        infos: list[PnpmInfo] = []
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
        self._stats = PnpmStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PnpmStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PnpmInfo]:
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
        """Scaffold hardened pnpm workspace and .npmrc snippets."""
        return """\
# pnpm-workspace.yaml — explicit workspace packages
packages:
  - 'packages/*'
  - 'apps/*'

# .npmrc — secure defaults
strict-peer-dependencies=true
auto-install-peers=false
ignore-scripts=true
# registry=https://registry.npmjs.org/
# //registry.npmjs.org/:_authToken=${NPM_TOKEN}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pnpm configs: none found"
        return (
            f"Pnpm configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pnpm analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            packages = ", ".join(info.packages[:6]) if info.packages else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.packages)} package path(s)"
            )
            if info.packages:
                lines.append(f"      packages: {packages}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
