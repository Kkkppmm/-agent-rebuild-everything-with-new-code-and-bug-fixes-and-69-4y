"""TrivyAnalyzer — audit Trivy ignore files and CLI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

TRIVY_IGNORE_NAMES = (".trivyignore", ".trivyignore.yaml", ".trivyignore.yml")
TRIVY_CONFIG_NAMES = ("trivy.yaml", "trivy.yml", ".trivy.yaml", ".trivy.yml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|TRIVY_[A-Z0-9]{20,}|npm_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repository|registry|url|endpoint|mirror)\s*[:=]\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"^\s*(?:insecure|skip-tls-verify|skip_tls_verify|insecureSkipTLSVerify)\s*:\s*true\s*$",
    re.IGNORECASE,
)
EXIT_CODE_ZERO_PATTERN = re.compile(
    r"^\s*(?:exit-code|exitCode)\s*:\s*0\s*$",
    re.IGNORECASE,
)
IGNORE_UNFIXED_PATTERN = re.compile(
    r"^\s*(?:ignore-unfixed|ignoreUnfixed)\s*:\s*true\s*$",
    re.IGNORECASE,
)
SKIP_DB_UPDATE_PATTERN = re.compile(
    r"^\s*(?:skip-update|skipUpdate|no-progress)\s*:\s*true\s*$",
    re.IGNORECASE,
)
BROAD_SKIP_DIR_PATTERN = re.compile(
    r"^\s*(?:skip-dirs|skipDirs|skip-files|skipFiles)\s*:\s*\[[^\]]*(?:\*|\*\*)[^\]]*\]",
    re.IGNORECASE,
)
LOW_SEVERITY_PATTERN = re.compile(
    r"^\s*severity\s*:\s*[\"']?(?:UNKNOWN|LOW)(?:,\s*(?:UNKNOWN|LOW))*[\"']?\s*$",
    re.IGNORECASE,
)
WILDCARD_IGNORE_PATTERN = re.compile(r"^\s*(?:\*|\*\*)\s*(?:#.*)?$")
BROAD_IGNORE_PATTERN = re.compile(
    r"^\s*(?:CVE-\*|GHSA-\*|AVD-\*|OSV-\*)\s*$",
    re.IGNORECASE,
)
REGISTRY_CREDENTIALS_PATTERN = re.compile(
    r"^\s*(?:credentials|username|password)\s*:\s*[\"']?[^\"'\s{][^\s\"']*[\"']?\s*$",
    re.IGNORECASE,
)
DISABLED_SCANNER_PATTERN = re.compile(
    r"^\s*(?:security-checks|scanners)\s*:\s*\[[^\]]*(?:none|vuln|config|secret)[^\]]*\]",
    re.IGNORECASE,
)
EMPTY_IGNORE_FILE_PATTERN = re.compile(r"^\s*$")


@dataclass
class TrivyFinding:
    """A security or best-practice issue in a Trivy config."""

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
class TrivyInfo:
    """Parsed metadata about a Trivy config file."""

    path: str
    config_type: str = "ignore"
    ignore_entries: int = 0
    skip_dirs: int = 0
    skip_files: int = 0
    has_severity: bool = False
    lines: int = 0


@dataclass
class TrivyStats:
    """Aggregate Trivy analysis statistics."""

    configs: int
    files: int
    findings: int
    ignore_files: int = 0
    cli_files: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_trivy_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in TRIVY_IGNORE_NAMES:
        return True
    return lower in TRIVY_CONFIG_NAMES


def _config_type(path: Path) -> str:
    lower = path.name.lower()
    if lower.startswith(".trivyignore") or lower == ".trivyignore":
        return "ignore"
    return "cli"


class TrivyAnalyzer:
    """Audit Trivy ignore files and CLI configs for hardcoded tokens, broad ignores, and weak defaults.

    Scans `.trivyignore` and `trivy.yaml` configs for embedded credentials, wildcard suppressions,
    fail-open exit codes, and insecure registry/database settings.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[TrivyFinding] | None = None
        self._stats: TrivyStats | None = None
        self._infos: list[TrivyInfo] | None = None

    def files(self) -> list[Path]:
        """Return Trivy config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_trivy_file(path):
                paths.append(path)
        return paths

    def _analyze_ignore_file(self, path: Path) -> tuple[list[TrivyFinding], TrivyInfo]:
        findings: list[TrivyFinding] = []
        rel = str(path.relative_to(self.root))
        config_type = _config_type(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TrivyInfo(path=rel, config_type=config_type)

        info = TrivyInfo(path=rel, config_type=config_type, lines=len(raw_lines))
        ignore_entries = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            ignore_entries += 1

            if WILDCARD_IGNORE_PATTERN.match(stripped):
                findings.append(
                    TrivyFinding(
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
                    TrivyFinding(
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
                    TrivyFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Trivy ignore file — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        info.ignore_entries = ignore_entries

        if info.lines > 0 and ignore_entries == 0 and not any(
            stripped.startswith("#") or not stripped.strip()
            for stripped in (l.strip() for l in raw_lines)
            if stripped
        ):
            findings.append(
                TrivyFinding(
                    kind="empty_ignore",
                    severity="low",
                    message="Trivy ignore file has no active entries — remove unused file or document purpose",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        return findings, info

    def _analyze_cli_file(self, path: Path) -> tuple[list[TrivyFinding], TrivyInfo]:
        findings: list[TrivyFinding] = []
        rel = str(path.relative_to(self.root))
        config_type = _config_type(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TrivyInfo(path=rel, config_type=config_type)

        info = TrivyInfo(path=rel, config_type=config_type, lines=len(raw_lines))
        in_skip_dirs = False
        in_skip_files = False
        in_severity = False
        severity_only_low = True

        for lineno, line in enumerate(raw_lines, start=1):
            if re.search(r"^\s*(?:skip-dirs|skipDirs)\s*:", line, re.IGNORECASE):
                in_skip_dirs = True
                in_skip_files = False
                in_severity = False
            elif re.search(r"^\s*(?:skip-files|skipFiles)\s*:", line, re.IGNORECASE):
                in_skip_files = True
                in_skip_dirs = False
                in_severity = False
            elif re.search(r"^\s*severity\s*:", line, re.IGNORECASE):
                in_severity = True
                in_skip_dirs = False
                in_skip_files = False
                severity_only_low = True
            elif re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                if in_severity and severity_only_low:
                    findings.append(
                        TrivyFinding(
                            kind="low_severity_threshold",
                            severity="medium",
                            message="severity limited to UNKNOWN/LOW — include HIGH and CRITICAL in scan thresholds",
                            path=rel,
                            lineno=lineno - 1,
                            line=line,
                        )
                    )
                in_skip_dirs = False
                in_skip_files = False
                in_severity = False

            if in_severity and re.search(
                r"^\s*-\s*(?:CRITICAL|HIGH|MEDIUM)\s*$", line, re.IGNORECASE
            ):
                severity_only_low = False

            if (in_skip_dirs or in_skip_files) and re.search(r"\*\*?", line):
                findings.append(
                    TrivyFinding(
                        kind="broad_skip",
                        severity="high",
                        message="wildcard skip-dirs/skip-files excludes large paths from scanning — use specific directories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Trivy config — use TRIVY_USERNAME/TRIVY_PASSWORD env vars or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP registry or database URL — use HTTPS for Trivy DB and registry mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="insecure_tls",
                        severity="high",
                        message="TLS verification disabled — do not skip TLS verify for registries or vulnerability DB",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EXIT_CODE_ZERO_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="fail_open",
                        severity="high",
                        message="exit-code 0 allows CI to pass with vulnerabilities — use exit-code 1 for blocking scans",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if IGNORE_UNFIXED_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="ignore_unfixed",
                        severity="medium",
                        message="ignore-unfixed hides vulnerabilities without patches — document risk acceptance",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_DB_UPDATE_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="stale_db",
                        severity="medium",
                        message="vulnerability database updates disabled — keep Trivy DB fresh for accurate scans",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BROAD_SKIP_DIR_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="broad_skip",
                        severity="high",
                        message="wildcard skip-dirs/skip-files excludes large paths from scanning — use specific directories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOW_SEVERITY_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="low_severity_threshold",
                        severity="medium",
                        message="severity limited to UNKNOWN/LOW — include HIGH and CRITICAL in scan thresholds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if REGISTRY_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    TrivyFinding(
                        kind="registry_credentials",
                        severity="high",
                        message="inline registry credentials — use TRIVY_USERNAME/TRIVY_PASSWORD or Docker config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            skip_dirs_match = re.search(
                r"^\s*(?:skip-dirs|skipDirs)\s*:\s*\[([^\]]+)\]",
                line,
                re.IGNORECASE,
            )
            if skip_dirs_match:
                info.skip_dirs += len(
                    [p for p in skip_dirs_match.group(1).split(",") if p.strip()]
                )

            skip_files_match = re.search(
                r"^\s*(?:skip-files|skipFiles)\s*:\s*\[([^\]]+)\]",
                line,
                re.IGNORECASE,
            )
            if skip_files_match:
                info.skip_files += len(
                    [p for p in skip_files_match.group(1).split(",") if p.strip()]
                )

            if re.search(r"^\s*severity\s*:", line, re.IGNORECASE):
                info.has_severity = True

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[TrivyFinding], TrivyInfo]:
        config_type = _config_type(path)
        if config_type == "ignore":
            return self._analyze_ignore_file(path)
        return self._analyze_cli_file(path)

    def analyze(self) -> list[TrivyFinding]:
        """Scan Trivy config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TrivyFinding] = []
        infos: list[TrivyInfo] = []
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
        self._stats = TrivyStats(
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
    def stats(self) -> TrivyStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TrivyInfo]:
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
        """Scaffold a hardened Trivy config template."""
        return """\
# Trivy config — https://aquasecurity.github.io/trivy/latest/docs/references/configuration/config-file/
scan:
  severity:
    - CRITICAL
    - HIGH
    - MEDIUM
  exit-code: 1
  ignore-unfixed: false
  timeout: 5m
db:
  skip-update: false
# Example time-bound ignore in .trivyignore (one CVE/GHSA per line):
# CVE-2024-12345
# GHSA-xxxx-yyyy-zzzz
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Trivy: none found"
        return (
            f"Trivy: {stats.configs} file(s) ({stats.ignore_files} ignore, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Trivy config analysis:",
            f"  configs: {stats.configs}",
            f"  ignore files: {stats.ignore_files}",
            f"  cli files: {stats.cli_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: type={info.config_type}, "
                f"ignores={info.ignore_entries}, skip_dirs={info.skip_dirs}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
