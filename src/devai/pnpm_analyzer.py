"""PnpmAnalyzer — audit pnpm-workspace.yaml, .npmrc, and .pnpmfile.cjs for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PNPM_WORKSPACE_NAMES = ("pnpm-workspace.yaml", "pnpm-workspace.yml")
PNPM_CONFIG_NAMES = (".npmrc",)
PNPM_HOOK_NAMES = (".pnpmfile.cjs", ".pnpmfile.js")
PNPM_LOCK_NAMES = ("pnpm-lock.yaml",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|_authToken|_auth)\s*[=:]\s*"
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
TRUST_POLICY_OFF_PATTERN = re.compile(
    r"trust[-_]?policy\s*=\s*(?:off|false|none)",
    re.IGNORECASE,
)
SHAMEFULLY_HOIST_PATTERN = re.compile(
    r"shamefully[-_]?hoist\s*=\s*true",
    re.IGNORECASE,
)
STRICT_SSL_OFF_PATTERN = re.compile(
    r"strict[-_]?ssl\s*=\s*false",
    re.IGNORECASE,
)
UNPINNED_CATALOG_PATTERN = re.compile(
    r"(?:latest|\*|LATEST|workspace:\*)",
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
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PnpmInfo:
    """Parsed metadata from a pnpm configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    packages: list[str] = field(default_factory=list)
    catalogs: list[str] = field(default_factory=list)


@dataclass
class PnpmStats:
    """Aggregate statistics from pnpm analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name in PNPM_WORKSPACE_NAMES:
        return "workspace"
    if name in PNPM_HOOK_NAMES:
        return "pnpmfile"
    if name in PNPM_LOCK_NAMES:
        return "lockfile"
    if name in PNPM_CONFIG_NAMES:
        return "npmrc"
    return "unknown"


def _is_pnpm_file(path: Path) -> bool:
    name = path.name
    if name in (*PNPM_WORKSPACE_NAMES, *PNPM_HOOK_NAMES, *PNPM_LOCK_NAMES):
        return True
    if name in PNPM_CONFIG_NAMES:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            return any(
                marker in text
                for marker in (
                    "shamefully-hoist",
                    "trust-policy",
                    "public-hoist-pattern",
                    "pnpmfile=",
                    "catalog:",
                    "link-workspace-packages",
                )
            )
        except OSError:
            return False
    return False


class PnpmAnalyzer:
    """Audit pnpm workspace and configuration files for security issues.

    Scans pnpm-workspace.yaml, .npmrc, .pnpmfile.cjs, and pnpm-lock.yaml for
    hardcoded tokens, insecure registry URLs, disabled trust policies,
    shamefully-hoist settings, credentials in git URLs, and dangerous hooks.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root).resolve()
        self._findings: list[PnpmFinding] | None = None
        self._stats: PnpmStats | None = None
        self._infos: list[PnpmInfo] | None = None

    def configs(self) -> list[Path]:
        """Return pnpm configuration paths found in the project."""
        paths: list[Path] = []
        for path in self.root.rglob("*"):
            if any(part.startswith(".") and part not in {".", ".."} for part in path.parts):
                if path.name not in (*PNPM_CONFIG_NAMES, *PNPM_HOOK_NAMES):
                    continue
            if path.is_file() and _is_pnpm_file(path):
                paths.append(path)
        return sorted(set(paths))

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PnpmFinding],
        info: PnpmInfo,
        *,
        in_catalog: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in pnpm config — use env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in config — use NPM_TOKEN env var or CI secrets",
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
                    message="AWS access key in pnpm config — use credential helpers or secret stores",
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
                    message="insecure HTTP registry URL — use HTTPS for package registries",
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
                    message="credentials embedded in git source URL — use .npmrc auth tokens or SSH keys",
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
                    message="curl|sh pattern in config — avoid piping remote scripts to shell",
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
                    message="sensitive host path reference — avoid bundling credentials in builds",
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
                    message="dangerous script in pnpm config — review install hooks and pnpmfile logic",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRUST_POLICY_OFF_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="trust_policy_off",
                    severity="high",
                    message="trust-policy disabled — pnpm will not verify package integrity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHAMEFULLY_HOIST_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="shamefully_hoist",
                    severity="medium",
                    message="shamefully-hoist enabled — can break phantom dependency isolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_SSL_OFF_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="strict_ssl_off",
                    severity="high",
                    message="strict-ssl disabled — TLS certificate validation is bypassed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_CATALOG_PATTERN.search(line) and (
            in_catalog or "catalog" in line.lower()
        ):
            findings.append(
                PnpmFinding(
                    kind="unpinned_catalog",
                    severity="low",
                    message="unpinned catalog version — pin dependency versions for reproducible builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        pkg_match = re.match(r"^\s*-\s*['\"]?([^'\"#\s]+)['\"]?", stripped)
        if pkg_match and info.file_kind == "workspace":
            pkg = pkg_match.group(1)
            if pkg not in info.packages:
                info.packages.append(pkg)

    def _analyze_file(self, path: Path) -> tuple[list[PnpmFinding], PnpmInfo]:
        findings: list[PnpmFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PnpmInfo(path=rel, file_kind=file_kind)

        info = PnpmInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        in_catalog = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if re.match(r"^catalog\s*:", stripped, re.IGNORECASE):
                in_catalog = True
            elif in_catalog and stripped and not stripped.startswith("#") and not line.startswith(" "):
                in_catalog = False
            self._scan_line(line, lineno, rel, findings, info, in_catalog=in_catalog)

        if file_kind == "workspace" and not info.packages:
            findings.append(
                PnpmFinding(
                    kind="empty_workspace",
                    severity="low",
                    message="pnpm workspace has no packages defined — verify workspace config",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if file_kind == "lockfile" and not path.exists():
            pass
        elif file_kind == "lockfile":
            lock_text = "\n".join(raw_lines)
            if "lockfileVersion" not in lock_text:
                findings.append(
                    PnpmFinding(
                        kind="invalid_lockfile",
                        severity="medium",
                        message="pnpm-lock.yaml missing lockfileVersion — regenerate lockfile",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[PnpmFinding]:
        """Run analysis and return all findings."""
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
            configs=len(paths),
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
# pnpm-workspace.yaml
packages:
  - "apps/*"
  - "packages/*"

# .npmrc — use env vars for tokens, never commit secrets
# //registry.npmjs.org/:_authToken=${NPM_TOKEN}
strict-ssl=true
trust-policy=strict
auto-install-peers=true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "pnpm configs: none found"
        return (
            f"pnpm configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "pnpm analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            pkgs = ", ".join(info.packages[:6]) if info.packages else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): packages={pkgs}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
