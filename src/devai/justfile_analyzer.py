"""JustfileAnalyzer — audit just command runner files for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JUSTFILE_NAMES = ("justfile", "Justfile", ".justfile")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*:=\s*"
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
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:eval\s*\(|\bsh\s+-c\b)",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+.*--force", re.IGNORECASE)
DOTENV_LOAD_PATTERN = re.compile(r"set\s+dotenv-load\b", re.IGNORECASE)
EXPORT_SECRET_PATTERN = re.compile(
    r"export\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY)[A-Z0-9_]*\s*:=",
    re.IGNORECASE,
)
RECIPE_PATTERN = re.compile(r"^([a-zA-Z0-9_-]+)\s*:")


@dataclass
class JustfileFinding:
    """A security or best-practice issue in a justfile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JustfileInfo:
    """Parsed metadata about a justfile."""

    path: str
    recipes: list[str] = field(default_factory=list)
    has_dotenv_load: bool = False
    lines: int = 0


@dataclass
class JustfileStats:
    """Aggregate justfile analysis statistics."""

    justfiles: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_justfile(path: Path) -> bool:
    return path.name in JUSTFILE_NAMES


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class JustfileAnalyzer:
    """Audit justfiles for security risks and best practices.

    Scans justfile/Justfile for curl-pipe-to-shell, hardcoded secrets in
    variables, sudo usage, destructive rm -rf, chmod 777, insecure HTTP URLs,
    SCM credentials, dotenv-load settings, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JustfileFinding] | None = None
        self._stats: JustfileStats | None = None
        self._infos: list[JustfileInfo] | None = None

    def justfiles(self) -> list[Path]:
        """Return justfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_justfile(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[JustfileFinding],
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        raw: str,
    ) -> None:
        findings.append(
            JustfileFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=raw.strip(),
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[JustfileFinding], JustfileInfo]:
        findings: list[JustfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JustfileInfo(path=rel)

        info = JustfileInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            recipe_match = RECIPE_PATTERN.match(line)
            if recipe_match:
                info.recipes.append(recipe_match.group(1))

            if DOTENV_LOAD_PATTERN.search(line):
                info.has_dotenv_load = True
                self._add_finding(
                    findings,
                    "dotenv_load",
                    "medium",
                    "dotenv-load enabled — ensure .env is gitignored and secrets are not committed",
                    rel,
                    lineno,
                    raw,
                )

            if HARDCODED_SECRET_PATTERN.search(line) or ENV_SECRET_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "hardcoded_secret",
                    "high",
                    "hardcoded secret in justfile — use env vars or secret stores",
                    rel,
                    lineno,
                    raw,
                )

            if EXPORT_SECRET_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "export_secret",
                    "high",
                    "exported secret variable in justfile — inject via environment instead",
                    rel,
                    lineno,
                    raw,
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "aws_access_key",
                    "high",
                    "AWS access key in justfile — use credential helpers or secret stores",
                    rel,
                    lineno,
                    raw,
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "curl_pipe_shell",
                    "high",
                    "piping curl/wget to shell is unsafe — vendor scripts with checksum verification",
                    rel,
                    lineno,
                    raw,
                )

            if RM_RF_ROOT_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "destructive_rm",
                    "high",
                    "rm -rf on root or home directory is dangerous",
                    rel,
                    lineno,
                    raw,
                )

            if SUDO_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "sudo_usage",
                    "medium",
                    "sudo in recipes can escalate privileges unexpectedly",
                    rel,
                    lineno,
                    raw,
                )

            if CHMOD_777_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "chmod_777",
                    "high",
                    "chmod 777 grants world-writable permissions",
                    rel,
                    lineno,
                    raw,
                )

            if INSECURE_HTTP_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "insecure_http",
                    "medium",
                    "insecure HTTP URL — use HTTPS for downloads and remote sources",
                    rel,
                    lineno,
                    raw,
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "scm_credentials",
                    "high",
                    "credentials embedded in SCM URL — use SSH keys or credential helpers",
                    rel,
                    lineno,
                    raw,
                )

            if DANGEROUS_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "dangerous_shell",
                    "medium",
                    "dangerous shell pattern (eval or sh -c) — prefer explicit commands",
                    rel,
                    lineno,
                    raw,
                )

            if FORCE_PUSH_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "git_force_push",
                    "medium",
                    "git push --force can overwrite remote history",
                    rel,
                    lineno,
                    raw,
                )

        return findings, info

    def analyze(self) -> list[JustfileFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JustfileFinding] = []
        infos: list[JustfileInfo] = []
        paths = self.justfiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = JustfileStats(
            justfiles=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JustfileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JustfileInfo]:
        """Return parsed justfile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no justfiles)."""
        self.analyze()
        stats = self.stats
        if stats.justfiles == 0:
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
        """Scaffold a hardened justfile snippet with secure defaults."""
        return """\
# justfile — hardened defaults for just projects
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
# set dotenv-load  # Only if .env is gitignored and has no committed secrets

export NODE_ENV := "development"
# export API_KEY := env_var("API_KEY")  # Inject via CI or local env

default:
    @just --list

setup:
    npm ci
    # Avoid: curl https://example.com/install.sh | sh

test:
    npm test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.justfiles == 0:
            return "Justfiles: none found"
        return (
            f"Justfiles: {stats.justfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Justfile analysis:",
            f"  justfiles: {stats.justfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            recipes = ", ".join(info.recipes[:8]) if info.recipes else "none"
            lines.append(
                f"  - {info.path}: {len(info.recipes)} recipe(s), "
                f"dotenv_load={info.has_dotenv_load}"
            )
            lines.append(f"    recipes: {recipes}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
