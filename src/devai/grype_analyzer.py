"""GrypeAnalyzer — audit Grype ignore files and CLI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

GRYPE_IGNORE_NAMES = (".grypeignore",)
GRYPE_CONFIG_NAMES = (
    ".grype.yaml",
    ".grype.yml",
    "grype.yaml",
    "grype.yml",
)
GRYPE_CONFIG_DIRS = ("grype",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|ANCHORE_[A-Z0-9]{20,}|npm_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repository|registry|url|endpoint|mirror|proxy|http-proxy)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"^\s*(?:insecure-skip-tls-verify|insecureSkipTLSVerify|skip-tls-verify|skip_tls_verify)\s*:\s*true\s*$",
    re.IGNORECASE,
)
FAIL_OPEN_SEVERITY_PATTERN = re.compile(
    r"^\s*(?:fail-on-severity|failOnSeverity|fail-on)\s*:\s*[\"']?(?:none|negligible|unknown)[\"']?\s*$",
    re.IGNORECASE,
)
DISABLE_DB_UPDATE_PATTERN = re.compile(
    r"^\s*(?:auto-update|autoUpdate|update)\s*:\s*false\s*$",
    re.IGNORECASE,
)
DISABLE_DB_AGE_PATTERN = re.compile(
    r"^\s*(?:validate-age|validateAge)\s*:\s*false\s*$",
    re.IGNORECASE,
)
BROAD_IGNORE_PATTERN = re.compile(
    r"^\s*(?:CVE-\*|GHSA-\*|OSV-\*|\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
WILDCARD_IGNORE_PATTERN = re.compile(r"^\s*(?:\*|\*\*)\s*(?:#.*)?$")
INLINE_REGISTRY_AUTH_PATTERN = re.compile(
    r"^\s*(?:auth|credentials|token|username|password)\s*:\s*[\"']?[^\"'\s{][^\s\"']*[\"']?\s*$",
    re.IGNORECASE,
)
IGNORE_WITHOUT_REASON_PATTERN = re.compile(
    r"^\s*-\s*vulnerability\s*:\s*",
    re.IGNORECASE,
)
REASON_PATTERN = re.compile(r"^\s*reason\s*:", re.IGNORECASE)
ONLY_FIXED_PATTERN = re.compile(
    r"^\s*(?:only-fixed|onlyFixed)\s*:\s*true\s*$",
    re.IGNORECASE,
)
BROAD_PACKAGE_IGNORE_PATTERN = re.compile(
    r"^\s*-\s*package\s*:\s*\n?\s*name\s*:\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
MATCH_EVERYTHING_PATTERN = re.compile(
    r"^\s*(?:match-everything|matchEverything)\s*:\s*true\s*$",
    re.IGNORECASE,
)


@dataclass
class GrypeFinding:
    """A security or best-practice issue in a Grype config."""

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
class GrypeInfo:
    """Parsed metadata about a Grype config file."""

    path: str
    config_type: str = "ignore"
    ignore_entries: int = 0
    has_fail_on_severity: bool = False
    has_db_config: bool = False
    lines: int = 0


@dataclass
class GrypeStats:
    """Aggregate Grype analysis statistics."""

    configs: int
    files: int
    findings: int
    ignore_files: int = 0
    cli_files: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_grype_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in GRYPE_IGNORE_NAMES:
        return True
    if lower in GRYPE_CONFIG_NAMES:
        return True
    if path.parent.name.lower() in GRYPE_CONFIG_DIRS and lower in (
        "config.yaml",
        "config.yml",
        ".grype.yaml",
        ".grype.yml",
    ):
        return True
    return False


def _config_type(path: Path) -> str:
    lower = path.name.lower()
    if lower == ".grypeignore":
        return "ignore"
    return "cli"


class GrypeAnalyzer:
    """Audit Grype ignore files and CLI configs for hardcoded tokens, broad ignores, and weak defaults.

    Scans `.grypeignore` and `.grype.yaml` configs for embedded credentials, wildcard suppressions,
    fail-open severity thresholds, and insecure registry/database settings.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[GrypeFinding] | None = None
        self._stats: GrypeStats | None = None
        self._infos: list[GrypeInfo] | None = None

    def files(self) -> list[Path]:
        """Return Grype config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_grype_file(path):
                paths.append(path)
        return paths

    def _analyze_ignore_file(self, path: Path) -> tuple[list[GrypeFinding], GrypeInfo]:
        findings: list[GrypeFinding] = []
        rel = str(path.relative_to(self.root))
        config_type = _config_type(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GrypeInfo(path=rel, config_type=config_type)

        info = GrypeInfo(path=rel, config_type=config_type, lines=len(raw_lines))
        ignore_entries = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            ignore_entries += 1

            if WILDCARD_IGNORE_PATTERN.match(stripped):
                findings.append(
                    GrypeFinding(
                        kind="broad_ignore",
                        severity="high",
                        message="wildcard ignore suppresses all vulnerabilities — use specific CVE/GHSA IDs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif BROAD_IGNORE_PATTERN.match(stripped):
                findings.append(
                    GrypeFinding(
                        kind="broad_ignore",
                        severity="high",
                        message="prefix wildcard ignore pattern — scope suppressions to specific vulnerability IDs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Grype ignore file — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        info.ignore_entries = ignore_entries
        return findings, info

    def _analyze_cli_file(self, path: Path) -> tuple[list[GrypeFinding], GrypeInfo]:
        findings: list[GrypeFinding] = []
        rel = str(path.relative_to(self.root))
        config_type = _config_type(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GrypeInfo(path=rel, config_type=config_type)

        info = GrypeInfo(path=rel, config_type=config_type, lines=len(raw_lines))
        in_ignore_block = False
        pending_ignore = False
        has_reason = False

        for lineno, line in enumerate(raw_lines, start=1):
            if re.search(r"^\s*ignore\s*:", line, re.IGNORECASE):
                in_ignore_block = True
            elif in_ignore_block and re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                in_ignore_block = False
                pending_ignore = False
                has_reason = False

            if IGNORE_WITHOUT_REASON_PATTERN.search(line):
                pending_ignore = True
                has_reason = False
            elif pending_ignore and REASON_PATTERN.search(line):
                has_reason = True
            elif pending_ignore and re.match(r"^\s*-\s*", line) and not REASON_PATTERN.search(line):
                if not has_reason:
                    findings.append(
                        GrypeFinding(
                            kind="missing_reason",
                            severity="low",
                            message="vulnerability ignore without reason — document risk acceptance for each suppression",
                            path=rel,
                            lineno=lineno - 1,
                            line=line,
                        )
                    )
                pending_ignore = False
                has_reason = False

            if in_ignore_block and re.search(r"^\s*-\s*vulnerability\s*:\s*(?:\*|CVE-\*|GHSA-\*)", line, re.IGNORECASE):
                findings.append(
                    GrypeFinding(
                        kind="broad_ignore",
                        severity="high",
                        message="wildcard vulnerability ignore in config — scope suppressions to specific IDs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Grype config — use GRYPE_REGISTRY_AUTH or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP registry or database URL — use HTTPS for Grype DB and registry mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="insecure_tls",
                        severity="high",
                        message="TLS verification disabled — do not skip TLS verify for registries or vulnerability DB",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FAIL_OPEN_SEVERITY_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="fail_open",
                        severity="high",
                        message="fail-on-severity set to none/negligible — use medium or high to block CI on vulnerabilities",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_DB_UPDATE_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="stale_db",
                        severity="medium",
                        message="vulnerability database auto-update disabled — keep Grype DB fresh for accurate scans",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_DB_AGE_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="stale_db",
                        severity="medium",
                        message="database age validation disabled — enable validate-age to detect stale vulnerability data",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_REGISTRY_AUTH_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="registry_credentials",
                        severity="high",
                        message="inline registry credentials — use GRYPE_REGISTRY_AUTH or Docker config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ONLY_FIXED_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="only_fixed",
                        severity="medium",
                        message="only-fixed hides unfixed vulnerabilities — document risk acceptance if intentional",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if MATCH_EVERYTHING_PATTERN.search(line):
                findings.append(
                    GrypeFinding(
                        kind="broad_ignore",
                        severity="high",
                        message="match-everything suppresses all findings — remove or scope to specific packages",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if re.search(r"^\s*(?:fail-on-severity|failOnSeverity)\s*:", line, re.IGNORECASE):
                info.has_fail_on_severity = True

            if re.search(r"^\s*db\s*:", line, re.IGNORECASE):
                info.has_db_config = True

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GrypeFinding], GrypeInfo]:
        config_type = _config_type(path)
        if config_type == "ignore":
            return self._analyze_ignore_file(path)
        return self._analyze_cli_file(path)

    def analyze(self) -> list[GrypeFinding]:
        """Scan Grype config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GrypeFinding] = []
        infos: list[GrypeInfo] = []
        paths = self.files()
        ignore_files = 0
        cli_files = 0

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            if info.config_type == "ignore":
                ignore_files += 1
            else:
                cli_files += 1

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = GrypeStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            ignore_files=ignore_files,
            cli_files=cli_files,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GrypeStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GrypeInfo]:
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Grype config template."""
        return """\
# Grype config — https://github.com/anchore/grype#configuration
check:
  fail-on-severity: high
  only-fixed: false
db:
  auto-update: true
  validate-age: true
  validate-age-hours: 24
# Example time-bound ignore in .grypeignore (one CVE/GHSA per line):
# CVE-2024-12345
# GHSA-xxxx-yyyy-zzzz
# Or in config:
# ignore:
#   - vulnerability: CVE-2024-12345
#     reason: "tracked in SEC-456, expires 2026-09-01"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Grype: none found"
        return (
            f"Grype: {stats.configs} file(s) ({stats.ignore_files} ignore, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Grype config analysis:",
            f"  configs: {stats.configs}",
            f"  ignore files: {stats.ignore_files}",
            f"  cli files: {stats.cli_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: type={info.config_type}, "
                f"ignores={info.ignore_entries}, fail_on_severity={info.has_fail_on_severity}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
