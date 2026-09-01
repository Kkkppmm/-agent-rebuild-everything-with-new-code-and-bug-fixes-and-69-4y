"""GoModAnalyzer — audit go.mod, go.sum, go.work, and go.env for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GO_MOD_NAMES = ("go.mod",)
GO_SUM_NAMES = ("go.sum",)
GO_WORK_NAMES = ("go.work",)
GO_ENV_NAMES = ("go.env", ".go.env")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*"
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
    r"https?://[^:@\s]+:[^@\s]+@|"
    r"(?:^|\s)[a-z0-9.-]+/[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
REPLACE_LOCAL_PATTERN = re.compile(
    r"=>\s*(?:\.\./|\./|/|[A-Za-z]:\\)",
    re.IGNORECASE,
)
REPLACE_UNPINNED_PATTERN = re.compile(
    r"=>\s*[^\s]+(?:#|@)(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
GOSUMDB_OFF_PATTERN = re.compile(r"GOSUMDB\s*=\s*(?:off|\"off\"|'off')", re.IGNORECASE)
GONOSUMDB_BROAD_PATTERN = re.compile(
    r"GONOSUMDB\s*=\s*(?:\*|all|\"\\*\"|'\\*')",
    re.IGNORECASE,
)
GOPROXY_INSECURE_PATTERN = re.compile(
    r"GOPROXY\s*=\s*[^\n]*(?:http://(?!localhost|127\.0\.0\.1)|\bdirect\b)",
    re.IGNORECASE,
)
GOINSECURE_BROAD_PATTERN = re.compile(
    r"GOINSECURE\s*=\s*(?:\*|all|\"\\*\"|'\\*'|.*,)",
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
GO_GENERATE_PATTERN = re.compile(r"^\s*//go:generate\s+(.+)$", re.IGNORECASE)
MODULE_URL_PATTERN = re.compile(
    r"(?:module|require|replace)\s+([^\s]+)",
    re.IGNORECASE,
)
DANGEROUS_GENERATE_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)


@dataclass
class GoModFinding:
    """A security or best-practice issue in a Go module configuration file."""

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
class GoModInfo:
    """Parsed metadata about a Go module configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    modules: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    replaces: list[str] = field(default_factory=list)


@dataclass
class GoModStats:
    """Aggregate Go module analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_go_mod_file(path: Path) -> bool:
    """Return True if the path looks like a Go module configuration file."""
    name = path.name
    return name in GO_MOD_NAMES or name in GO_SUM_NAMES or name in GO_WORK_NAMES or name in GO_ENV_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "go.mod":
        return "manifest"
    if name == "go.sum":
        return "lock"
    if name == "go.work":
        return "workspace"
    if name in GO_ENV_NAMES:
        return "go_env"
    return "unknown"


def _has_sumfile(directory: Path) -> bool:
    return (directory / "go.sum").exists()


class GoModAnalyzer:
    """Audit Go module configuration for security issues.

    Scans go.mod, go.sum, go.work, and go.env for hardcoded secrets,
    insecure module proxy settings, disabled checksum verification,
    credentials in module URLs, local replace directives, unpinned
    replacements, and missing go.sum lockfiles.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GoModFinding] | None = None
        self._stats: GoModStats | None = None
        self._infos: list[GoModInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Go module configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_go_mod_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GoModFinding],
        info: GoModInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped:
            return
        if stripped.startswith("//") and not stripped.lower().startswith("//go:generate"):
            return

        module_match = MODULE_URL_PATTERN.search(stripped)
        if module_match and stripped.lower().startswith(("module ", "require ", "replace ")):
            target = module_match.group(1)
            if stripped.lower().startswith("module "):
                info.modules.append(target)
            elif stripped.lower().startswith("require "):
                parts = target.split()
                if parts:
                    info.dependencies.append(parts[0])
            elif "=>" in stripped:
                info.replaces.append(stripped)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Go config — use GOPRIVATE and CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Go config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP module/proxy URL — use HTTPS for module proxies and VCS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in module URL — use netrc, SSH keys, or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPLACE_LOCAL_PATTERN.search(line) and "=>" in stripped:
            findings.append(
                GoModFinding(
                    kind="replace_local",
                    severity="medium",
                    message="local replace directive — avoid committing dev-only path overrides to production branches",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPLACE_UNPINNED_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="unpinned_replace",
                    severity="medium",
                    message="replace pinned to moving ref — pin replacements to version or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GOSUMDB_OFF_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="gosumdb_off",
                    severity="high",
                    message="GOSUMDB disabled — keep checksum verification enabled for supply-chain security",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GONOSUMDB_BROAD_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="gonosumdb_broad",
                    severity="high",
                    message="GONOSUMDB too broad — avoid disabling checksum DB for all modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GOPROXY_INSECURE_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="goproxy_insecure",
                    severity="medium",
                    message="insecure GOPROXY setting — use HTTPS proxies and avoid direct-only fetches in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GOINSECURE_BROAD_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="goinsecure_broad",
                    severity="high",
                    message="GOINSECURE too broad — do not disable TLS verification for module downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Go config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                GoModFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        generate_match = GO_GENERATE_PATTERN.match(stripped)
        if generate_match and DANGEROUS_GENERATE_PATTERN.search(generate_match.group(1)):
            findings.append(
                GoModFinding(
                    kind="dangerous_generate",
                    severity="high",
                    message="dangerous //go:generate command — review generated build steps for injection risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_go_mod(self, path: Path, rel: str) -> tuple[list[GoModFinding], GoModInfo]:
        findings: list[GoModFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GoModInfo(path=rel, file_kind="manifest")

        raw_lines = text.splitlines()
        info = GoModInfo(path=rel, lines=len(raw_lines), file_kind="manifest")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if not _has_sumfile(path.parent):
            findings.append(
                GoModFinding(
                    kind="missing_sum",
                    severity="low",
                    message="go.sum missing — commit checksum lockfile for reproducible builds",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[GoModFinding], GoModInfo]:
        findings: list[GoModFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GoModInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = GoModInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GoModFinding], GoModInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "go.mod":
            return self._analyze_go_mod(path, rel)
        return self._analyze_text_file(path, rel)

    def analyze(self) -> list[GoModFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GoModFinding] = []
        infos: list[GoModInfo] = []
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
        self._stats = GoModStats(
            configs=len({p.parent for p in paths if p.name == "go.mod"} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GoModStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GoModInfo]:
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
        """Scaffold a hardened go.env snippet with secure defaults."""
        return """\
# go.env — hardened defaults for Go projects
# Store private module credentials via CI secrets or ~/.netrc
GOPROXY=https://proxy.golang.org,direct
GOSUMDB=sum.golang.org
# GOPRIVATE=github.com/myorg/*
# GONOSUMDB=github.com/myorg/*
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Go module configs: none found"
        return (
            f"Go module configs: {stats.configs} module(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Go module analysis:",
            f"  modules: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            modules = ", ".join(info.modules[:4]) if info.modules else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.replaces)} replace(s)"
            )
            lines.append(f"    module: {modules}")
            lines.append(f"    dependencies: {deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
